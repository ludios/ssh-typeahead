# ssh-typeahead

When you type ahead during a local command, the keys wait in the terminal for
the shell's next prompt. During an `ssh -t` command they don't: ssh sends every
key to the far terminal, and the ones the command didn't read are lost when it
exits. ssh-typeahead brings those keys back to zsh's next prompt.

## How

Wrap the ssh, and the command on the far host:

	ssh-typeahead relay NONCE "$SSH_TYPEAHEAD_FILE" ssh -t HOST ssh-typeahead run NONCE COMMAND...

NONCE must be new for each command. Once the command has exited, `run` reads
the keys left on the far terminal, and `relay` stops sending keys and tells
`run` when all the ones it sent have arrived. `relay` appends them to
`$SSH_TYPEAHEAD_FILE`, and `ssh-typeahead.zsh` gives them to zle at the next
prompt, ahead of the keys typed since. The comment at the top of
[src/main.rs](src/main.rs) has the details.

The far terminal's line editing has already been applied to the keys it
queued, so a backspace typed during the command is applied, like a local
terminal would; and as on a local terminal, typing ^C, ^\ or ^Z drops what was
typed before it.

## Setup

- Install `ssh-typeahead` on both hosts.
- In zsh on the near host, `source ssh-typeahead.zsh`. It exports
  `SSH_TYPEAHEAD_FILE` only if `$XDG_RUNTIME_DIR` (or `$TMPDIR`) is a
  directory you own, which `relay` checks too, along with the file being named
  for its terminal.
- Use it only with a far host you trust as much as the near one: whatever
  `run` hands back gets typed into your shell.

## Limits

- Keys that the command read into a buffer but didn't use are gone, as are
  keys that it threw away (e.g. a pager quitting with `tcflush`).
- zle gets the keys, not a command started at the next prompt.
- A process left running on the far terminal can read the keys, and END with
  them; `run` then gives up after 2 seconds.

## Development

	cargo test
