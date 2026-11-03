//! Brings back the keys typed ahead during an `ssh -t` command that it didn't
//! read, so that the shell here gets them, as it would after a local command.
//!
//! On this host:     ssh-typeahead relay NONCE FILE ssh -t HOST ... ssh-typeahead run NONCE COMMAND...
//! On the far host:  ssh-typeahead run NONCE COMMAND [ARG]...
//!
//! `relay` runs ssh on a terminal of its own and relays this terminal to it,
//! like ssh relays its terminal to the far one. `run` runs the command there,
//! and once it has exited, they do a handshake in band:
//!
//! 1. `run` stops the far terminal's line editing and echo, so that even a
//!    half-typed line can be read, and prints STOP.
//! 2. `relay` stops sending keys, and sends END. Every key that `run` reads
//!    before END was typed but not read: first whatever was still queued on the
//!    far terminal, then whatever was on its way.
//! 3. `run` prints RETURN with those keys, and exits with the command's status.
//! 4. Once ssh has exited, `relay` appends the keys to FILE, for
//!    ssh-typeahead.zsh to give to zle. The keys typed after `relay` stopped
//!    sending are still queued on this terminal, and zle reads them after these.
//!
//! FILE is the $SSH_TYPEAHEAD_FILE that ssh-typeahead.zsh exports, which names
//! this terminal and the shell on it.
//!
//! NONCE, chosen anew for each command, marks the messages, so that the
//! command's output can't pass for them by accident. `run` can type into the
//! shell here, so use it only with a host trusted as much as this one.

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{self, IsTerminal, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use nix::libc;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::pty::{Winsize, openpty};
use nix::sys::signal::{self, SaFlags, SigAction, SigHandler, SigSet, Signal};
use nix::sys::termios::{self, InputFlags, LocalFlags, SetArg, SpecialCharacterIndices, Termios};
use nix::unistd;

/// How long `run` waits for END, which only fails to come when something is broken
const END_TIMEOUT: Duration = Duration::from_secs(2);
/// The most keys that `run` hands back
const MAX_KEYS: usize = 64 * 1024;
/// How long `relay` holds back output that could be the start of a message
const HOLD: Duration = Duration::from_millis(50);
/// The end of an APC string, and of RETURN's keys
const STRING_TERMINATOR: &[u8] = b"\x1b\\";

/// The handshake's messages for one NONCE. They're APC strings, which
/// terminals ignore if one ever gets through.
struct Markers {
	stop:         Vec<u8>,
	end:          Vec<u8>,
	/// RETURN continues with the keys in hex, then STRING_TERMINATOR
	return_start: Vec<u8>,
}

impl Markers {
	/// nonce: the NONCE that `relay` and `run` share
	fn new(nonce: &[u8]) -> Markers {
		let apc = |name: &str, end: &[u8]| [b"\x1b_ssh-typeahead-", name.as_bytes(), b";", nonce, end].concat();
		Markers {
			stop:         apc("stop", STRING_TERMINATOR),
			end:          apc("end", STRING_TERMINATOR),
			return_start: apc("return", b";"),
		}
	}
}

/// Returns where `needle` first starts in `haystack`, if anywhere.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
	haystack.windows(needle.len()).position(|window| window == needle)
}

fn to_hex(bytes: &[u8]) -> Vec<u8> {
	const DIGITS: &[u8; 16] = b"0123456789abcdef";
	bytes.iter().flat_map(|b| [DIGITS[(b >> 4) as usize], DIGITS[(b & 15) as usize]]).collect()
}

/// Returns the bytes, or None if `hex` isn't pairs of lowercase hex digits.
fn from_hex(hex: &[u8]) -> Option<Vec<u8>> {
	let digit = |c: u8| match c {
		b'0'..=b'9' => Some(c - b'0'),
		b'a'..=b'f' => Some(c - b'a' + 10),
		_ => None,
	};
	if !hex.len().is_multiple_of(2) {
		return None;
	}
	hex.chunks(2).map(|pair| Some(digit(pair[0])? << 4 | digit(pair[1])?)).collect()
}

/// Writes all of `data` to `fd`, which may take a few writes.
fn write_all(fd: BorrowedFd, mut data: &[u8]) -> io::Result<()> {
	while !data.is_empty() {
		match unistd::write(fd, data) {
			Ok(n) => data = &data[n..],
			Err(Errno::EINTR) => {}
			Err(e) => return Err(e.into()),
		}
	}
	Ok(())
}

/// Returns the exit status the way a shell reports it: 128 plus the signal's
/// number if a signal killed the process.
fn shell_status(status: ExitStatus) -> i32 {
	status.code().unwrap_or_else(|| 128 + status.signal().expect("a process that didn't exit was killed by a signal"))
}

/// Runs `argv` in a child process on this terminal and waits for it. ^C and ^\
/// reach the child, not us: we must live on to hand back the keys.
///
/// Returns the child's exit status the way a shell reports it.
fn run_command(argv: &[OsString]) -> io::Result<i32> {
	let mut stoppers = SigSet::empty();
	stoppers.add(Signal::SIGINT);
	stoppers.add(Signal::SIGQUIT);
	// Blocked until we ignore them; Command gives the child an empty mask
	stoppers.thread_block()?;
	let child = Command::new(&argv[0]).args(&argv[1..]).spawn();
	for sig in stoppers.iter() {
		// SAFETY: SIG_IGN installs no handler
		unsafe { signal::signal(sig, SigHandler::SigIgn) }?;
	}
	stoppers.thread_unblock()?;
	let mut child = match child {
		Ok(child) => child,
		Err(e) => {
			eprintln!("ssh-typeahead: {}: {e}", argv[0].to_string_lossy());
			return Ok(if e.kind() == io::ErrorKind::NotFound { 127 } else { 126 });
		}
	};
	Ok(shell_status(child.wait()?))
}

/// Prints STOP, then reads keys until END, or for at most END_TIMEOUT.
///
/// Returns the keys that came before END.
fn read_until_end(tty: BorrowedFd, markers: &Markers) -> io::Result<Vec<u8>> {
	write_all(tty, &markers.stop)?;
	let deadline = Instant::now() + END_TIMEOUT;
	let mut received = Vec::new();
	let mut buf = [0; 4096];
	loop {
		if let Some(end_at) = find(&received, &markers.end) {
			received.truncate(end_at);
			break;
		}
		if received.len() >= MAX_KEYS + markers.end.len() {
			break;
		}
		let left = deadline.saturating_duration_since(Instant::now());
		let mut fds = [PollFd::new(tty, PollFlags::POLLIN)];
		match poll(&mut fds, PollTimeout::try_from(left).unwrap_or(PollTimeout::MAX)) {
			Ok(0) => break,
			Ok(_) | Err(Errno::EINTR) => {}
			Err(e) => return Err(e.into()),
		}
		match unistd::read(tty, &mut buf) {
			Ok(0) => break,
			Ok(n) => received.extend_from_slice(&buf[..n]),
			Err(Errno::EINTR) => {}
			Err(e) => return Err(e.into()),
		}
	}
	received.truncate(MAX_KEYS);
	Ok(received)
}

/// tty:     the far terminal, which the command has finished with
/// markers: this NONCE's messages
///
/// Does steps 1 and 2 of the handshake. Returns the keys that were typed but
/// not read: the ones that the terminal still queued, as its line editing left
/// them (e.g. with a backspace applied), then the ones on their way, as typed.
fn unread_keys(tty: BorrowedFd, markers: &Markers) -> io::Result<Vec<u8>> {
	let saved = termios::tcgetattr(tty)?;
	let mut raw = saved.clone();
	raw.input_flags.remove(InputFlags::ICRNL | InputFlags::INLCR | InputFlags::IGNCR | InputFlags::ISTRIP | InputFlags::IXON);
	raw.local_flags.remove(LocalFlags::ICANON | LocalFlags::ECHO | LocalFlags::ECHONL | LocalFlags::ISIG | LocalFlags::IEXTEN);
	raw.control_chars[SpecialCharacterIndices::VMIN as usize] = 1;
	raw.control_chars[SpecialCharacterIndices::VTIME as usize] = 0;
	// TCSANOW, unlike TCSAFLUSH, keeps the queued keys that we're after
	termios::tcsetattr(tty, SetArg::TCSANOW, &raw)?;
	let keys = read_until_end(tty, markers);
	termios::tcsetattr(tty, SetArg::TCSANOW, &saved)?;
	keys
}

/// The far side: runs `argv`, then does the whole handshake if this is a terminal.
///
/// Returns the command's exit status, for `run` to exit with.
fn run(markers: &Markers, argv: &[OsString]) -> io::Result<i32> {
	let status = run_command(argv)?;
	let stdin = io::stdin();
	let tty = stdin.as_fd();
	// If the terminal has gone, so has anyone who would want the keys
	if stdin.is_terminal()
		&& let Ok(keys) = unread_keys(tty, markers)
	{
		let _ = write_all(tty, &[&markers.return_start[..], &to_hex(&keys), STRING_TERMINATOR].concat());
	}
	Ok(status)
}

/// A message from `run`, found in ssh's output
#[derive(Debug, PartialEq)]
enum Message {
	Stop,
	/// The keys, in hex
	Return(Vec<u8>),
}

/// pending: output from ssh that hasn't been passed on yet
/// markers: this NONCE's messages
///
/// Finds the messages from `run`. Returns (the output to pass on, the
/// messages, the end of `pending` to hold back, since it could be the start
/// of a message).
fn scan(mut pending: &[u8], markers: &Markers) -> (Vec<u8>, Vec<Message>, Vec<u8>) {
	let mut output = Vec::new();
	let mut messages = Vec::new();
	loop {
		let stop_at = find(pending, &markers.stop);
		let return_at = find(pending, &markers.return_start);
		if let Some(i) = stop_at.filter(|&i| return_at.is_none_or(|j| i < j)) {
			output.extend_from_slice(&pending[..i]);
			messages.push(Message::Stop);
			pending = &pending[i + markers.stop.len()..];
		} else if let Some(i) = return_at {
			let keys_at = i + markers.return_start.len();
			let Some(len) = find(&pending[keys_at..], STRING_TERMINATOR) else {
				// Its keys aren't all here yet, unless something's wrong
				if pending.len() - keys_at > 2 * MAX_KEYS {
					output.extend_from_slice(pending);
					return (output, messages, Vec::new());
				}
				output.extend_from_slice(&pending[..i]);
				return (output, messages, pending[i..].to_vec());
			};
			output.extend_from_slice(&pending[..i]);
			messages.push(Message::Return(pending[keys_at..keys_at + len].to_vec()));
			pending = &pending[keys_at + len + STRING_TERMINATOR.len()..];
		} else {
			break;
		}
	}
	let could_start = |tail: &[u8]| markers.stop.starts_with(tail) || markers.return_start.starts_with(tail);
	let longest = markers.stop.len().max(markers.return_start.len()) - 1;
	let held = (1..=pending.len().min(longest)).rev().find(|&n| could_start(&pending[pending.len() - n..])).unwrap_or(0);
	output.extend_from_slice(&pending[..pending.len() - held]);
	(output, messages, pending[pending.len() - held..].to_vec())
}

static WINDOW_CHANGED: AtomicBool = AtomicBool::new(false);

extern "C" fn note_window_change(_: libc::c_int) {
	WINDOW_CHANGED.store(true, Ordering::Relaxed);
}

nix::ioctl_read_bad!(get_window_size, libc::TIOCGWINSZ, Winsize);
nix::ioctl_write_ptr_bad!(set_window_size, libc::TIOCSWINSZ, Winsize);

fn window_size(tty: BorrowedFd) -> io::Result<Winsize> {
	let mut size = Winsize { ws_row: 0, ws_col: 0, ws_xpixel: 0, ws_ypixel: 0 };
	// SAFETY: TIOCGWINSZ fills in a winsize
	unsafe { get_window_size(tty.as_raw_fd(), &mut size) }?;
	Ok(size)
}

/// keyboard: this terminal, to read keys from
/// screen:   this terminal, to write output to
/// master:   the master side of ssh's terminal
/// markers:  this NONCE's messages
///
/// Relays keys to ssh, and its output back, doing our part of the handshake,
/// until ssh's terminal closes. Returns the keys that `run` handed back, or
/// None if it didn't.
fn relay_terminal(keyboard: BorrowedFd, screen: BorrowedFd, master: BorrowedFd, markers: &Markers) -> io::Result<Option<Vec<u8>>> {
	let mut stopped = false;
	let mut keys = None;
	let mut pending = Vec::new();
	let mut buf = vec![0; 65536];
	loop {
		if WINDOW_CHANGED.swap(false, Ordering::Relaxed) {
			let size = window_size(keyboard)?;
			// SAFETY: TIOCSWINSZ reads a winsize
			unsafe { set_window_size(master.as_raw_fd(), &size) }?;
		}
		let mut fds = vec![PollFd::new(master, PollFlags::POLLIN)];
		if !stopped {
			fds.push(PollFd::new(keyboard, PollFlags::POLLIN));
		}
		let timeout = if pending.is_empty() { PollTimeout::NONE } else { PollTimeout::try_from(HOLD).unwrap() };
		match poll(&mut fds, timeout) {
			Ok(0) => {
				// It wasn't the start of a message after all
				write_all(screen, &pending)?;
				pending.clear();
				continue;
			}
			Ok(_) => {}
			Err(Errno::EINTR) => continue,
			Err(e) => return Err(e.into()),
		}
		let master_ready = fds[0].any().unwrap_or(false);
		let keyboard_ready = fds.get(1).is_some_and(|fd| fd.any().unwrap_or(false));
		if keyboard_ready {
			let n = match unistd::read(keyboard, &mut buf) {
				Ok(n) => n,
				Err(Errno::EINTR) => continue,
				Err(e) => return Err(e.into()),
			};
			write_all(master, &buf[..n])?;
			// A keyboard at its end has nothing more to send
			stopped |= n == 0;
		}
		if master_ready {
			let n = match unistd::read(master, &mut buf) {
				Ok(n) => n,
				// Linux says EIO once every process has closed ssh's terminal
				Err(Errno::EIO) => 0,
				Err(Errno::EINTR) => continue,
				Err(e) => return Err(e.into()),
			};
			if n == 0 {
				write_all(screen, &pending)?;
				return Ok(keys);
			}
			pending.extend_from_slice(&buf[..n]);
			let (output, messages, rest) = scan(&pending, markers);
			pending = rest;
			write_all(screen, &output)?;
			for message in messages {
				match message {
					Message::Stop if !stopped => {
						stopped = true;
						write_all(master, &markers.end)?;
					}
					Message::Return(hex) if stopped && keys.is_none() => {
						keys = Some(from_hex(&hex).unwrap_or_default());
					}
					_ => {}
				}
			}
		}
	}
}

/// argv:   the command to run, i.e. ssh
/// cooked: the terminal settings to give it: this terminal's
/// size:   the window size to give it: this terminal's
///
/// Returns the child, and the master side of its new terminal.
fn spawn_on_terminal(argv: &[OsString], cooked: &Termios, size: &Winsize) -> io::Result<(Child, OwnedFd)> {
	let pty = openpty(size, cooked)?;
	// Otherwise ssh, and its ControlPersist master, would hold its own terminal open
	fcntl(&pty.master, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
	let mut command = Command::new(&argv[0]);
	command
		.args(&argv[1..])
		.stdin(Stdio::from(pty.slave.try_clone()?))
		.stdout(Stdio::from(pty.slave.try_clone()?))
		.stderr(Stdio::from(pty.slave));
	// SAFETY: setsid and ioctl are async-signal-safe
	unsafe {
		command.pre_exec(|| {
			unistd::setsid()?;
			// Make the new terminal this session's, so that SIGWINCH reaches ssh
			if libc::ioctl(0, libc::TIOCSCTTY, 0) == -1 {
				return Err(io::Error::last_os_error());
			}
			Ok(())
		});
	}
	Ok((command.spawn()?, pty.master))
}

/// keys:   keys handed back
/// cooked: this terminal's settings
///
/// Returns `keys` without any before a ^C, ^\ or ^Z (or whatever this terminal
/// uses instead), and without that key, since this terminal drops typeahead then.
fn without_cancelled<'a>(keys: &'a [u8], cooked: &Termios) -> &'a [u8] {
	if !cooked.local_flags.contains(LocalFlags::ISIG) || cooked.local_flags.contains(LocalFlags::NOFLSH) {
		return keys;
	}
	let cancellers = [SpecialCharacterIndices::VINTR, SpecialCharacterIndices::VQUIT, SpecialCharacterIndices::VSUSP]
		.map(|i| cooked.control_chars[i as usize]);
	match keys.iter().rposition(|k| cancellers.contains(k) && *k != libc::_POSIX_VDISABLE) {
		Some(i) => &keys[i + 1..],
		None => keys,
	}
}

/// path: FILE, the $SSH_TYPEAHEAD_FILE from ssh-typeahead.zsh
/// tty:  this terminal
///
/// Returns whether to write keys to it: whether it's named for this terminal
/// (not for one whose shell's $SSH_TYPEAHEAD_FILE we inherited, e.g. through
/// tmux), and is in a directory that only we can write to.
fn is_safe_keys_file(path: &Path, tty: BorrowedFd) -> bool {
	let Ok(tty_path) = unistd::ttyname(tty) else {
		return false;
	};
	let tty_name = tty_path.to_string_lossy().trim_start_matches("/dev/").replace('/', "-");
	let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
		return false;
	};
	let Ok(dir) = std::fs::metadata(dir) else {
		return false;
	};
	name.to_string_lossy().starts_with(&format!("ssh-typeahead-{tty_name}-"))
		&& dir.uid() == unistd::getuid().as_raw()
		&& dir.mode() & 0o022 == 0
}

/// The near side: runs `argv` (ssh) and relays this terminal to it. Afterwards,
/// appends any keys that came back to `keys_file`.
///
/// Returns ssh's exit status, for `relay` to exit with.
fn relay(markers: &Markers, keys_file: &Path, argv: &[OsString]) -> io::Result<i32> {
	let stdin = io::stdin();
	let stdout = io::stdout();
	let keyboard = stdin.as_fd();
	if !stdin.is_terminal() {
		// Nothing to relay, and no keys to bring back
		return Err(Command::new(&argv[0]).args(&argv[1..]).exec());
	}
	let cooked = termios::tcgetattr(keyboard)?;
	let (mut ssh, master) = spawn_on_terminal(argv, &cooked, &window_size(keyboard)?)?;
	let on_window_change = SigAction::new(SigHandler::Handler(note_window_change), SaFlags::empty(), SigSet::empty());
	// SAFETY: the handler only stores to an atomic
	unsafe { signal::sigaction(Signal::SIGWINCH, &on_window_change) }?;
	let mut raw = cooked.clone();
	termios::cfmakeraw(&mut raw);
	// Not TCSAFLUSH, which would drop the keys typed ahead before we started
	termios::tcsetattr(keyboard, SetArg::TCSANOW, &raw)?;
	let keys = relay_terminal(keyboard, stdout.as_fd(), master.as_fd(), markers);
	// TCSADRAIN keeps the keys typed after we stopped sending them
	termios::tcsetattr(keyboard, SetArg::TCSADRAIN, &cooked)?;
	let status = shell_status(ssh.wait()?);
	let keys = keys?.unwrap_or_default();
	// zle -U would stop at a NUL
	let keys: Vec<u8> = without_cancelled(&keys, &cooked).iter().copied().filter(|&k| k != 0).collect();
	if !keys.is_empty() && is_safe_keys_file(keys_file, keyboard) {
		OpenOptions::new()
			.append(true)
			.create(true)
			.mode(0o600)
			.custom_flags(libc::O_NOFOLLOW)
			.open(keys_file)?
			.write_all(&keys)?;
	}
	Ok(status)
}

fn main() {
	let args: Vec<OsString> = std::env::args_os().skip(1).collect();
	let result = match args.first().and_then(|a| a.to_str()) {
		Some("relay") if args.len() >= 4 => relay(&Markers::new(args[1].as_bytes()), Path::new(&args[2]), &args[3..]),
		Some("run") if args.len() >= 3 => run(&Markers::new(args[1].as_bytes()), &args[2..]),
		_ => {
			eprintln!("usage: ssh-typeahead relay NONCE FILE COMMAND [ARG]...");
			eprintln!("       ssh-typeahead run NONCE COMMAND [ARG]...");
			std::process::exit(2);
		}
	};
	match result {
		Ok(status) => std::process::exit(status),
		Err(e) => {
			eprintln!("ssh-typeahead: {e}");
			// What ssh exits with when it fails
			std::process::exit(255);
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn hex_round_trips() {
		let bytes: Vec<u8> = (0..=255).collect();
		assert_eq!(from_hex(&to_hex(&bytes)), Some(bytes));
		assert_eq!(from_hex(b"0"), None);
		assert_eq!(from_hex(b"+f"), None);
		assert_eq!(from_hex(b"AB"), None);
	}

	#[test]
	fn scan_finds_messages_and_passes_on_the_rest() {
		let markers = Markers::new(b"n1");
		let input = [b"out1", &markers.stop[..], b"out2", &markers.return_start[..], b"6869", STRING_TERMINATOR, b"out3"].concat();
		let (output, messages, held) = scan(&input, &markers);
		assert_eq!(output, b"out1out2out3");
		assert_eq!(messages, [Message::Stop, Message::Return(b"6869".to_vec())]);
		assert!(held.is_empty());
	}

	#[test]
	fn scan_holds_back_what_could_start_a_message() {
		let markers = Markers::new(b"n1");
		for split in 1..markers.stop.len() {
			let (output, messages, held) = scan(&[b"out", &markers.stop[..split]].concat(), &markers);
			assert_eq!((output, messages.len(), held), (b"out".to_vec(), 0, markers.stop[..split].to_vec()));
		}
		let partial_return = [&markers.return_start[..], b"68"].concat();
		let (output, messages, held) = scan(&partial_return, &markers);
		assert_eq!((output, messages.len(), held), (Vec::new(), 0, partial_return));
	}

	#[test]
	fn scan_ignores_another_nonce() {
		let markers = Markers::new(b"n1");
		let other = Markers::new(b"n2");
		let (output, messages, _) = scan(&other.stop, &markers);
		assert_eq!((output, messages.len()), (other.stop.clone(), 0));
	}

	#[test]
	fn without_cancelled_drops_through_the_last_canceller() {
		let pty = openpty(None, None).unwrap();
		let mut cooked = termios::tcgetattr(&pty.slave).unwrap();
		cooked.local_flags.insert(LocalFlags::ISIG);
		cooked.local_flags.remove(LocalFlags::NOFLSH);
		cooked.control_chars[SpecialCharacterIndices::VINTR as usize] = 3;
		assert_eq!(without_cancelled(b"ls\x03pwd\x03cd\r", &cooked), b"cd\r");
		assert_eq!(without_cancelled(b"ls\r", &cooked), b"ls\r");
		cooked.local_flags.insert(LocalFlags::NOFLSH);
		assert_eq!(without_cancelled(b"ls\x03cd", &cooked), b"ls\x03cd");
	}
}
