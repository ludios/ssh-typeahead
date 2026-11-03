# Gives zle the keys typed ahead during an `ssh -t` command that ran through
# `ssh-typeahead relay`, which that command didn't read. The relay appends them
# to $SSH_TYPEAHEAD_FILE, which names this terminal and this shell, in a
# directory that only we can write to.
#
# Source this from an interactive shell's zshrc.

() {
	local dir=${XDG_RUNTIME_DIR:-${TMPDIR:-}}
	# A directory that we own, and that the group and others can't write to,
	# as relay checks too: anyone who can write the file can type into this shell
	local -a safe=($dir(N/f:go-w:))
	if [[ ! -o interactive || -z $TTY || -z $dir || ${#safe} == 0 || ! -O $dir ]]; then
		return
	fi
	zmodload zsh/mapfile || return
	export SSH_TYPEAHEAD_FILE=${dir%/}/ssh-typeahead-${${TTY#/dev/}//\//-}-$$
	# Left by an earlier shell with our PID on this terminal, which died before
	# it could take them; they weren't typed for this shell
	rm -f -- $SSH_TYPEAHEAD_FILE

	# Pushes the keys all at once: zle reads them before anything still queued
	# on the terminal, which was typed after them, while separate pushes would
	# come out last first. $mapfile, unlike $(<file), keeps a final newline.
	_ssh_typeahead_push() {
		emulate -L zsh
		# Not for vared, whose line-init runs this too
		if [[ $CONTEXT != start || ! -f $SSH_TYPEAHEAD_FILE ]]; then
			return 0
		fi
		local keys=$mapfile[$SSH_TYPEAHEAD_FILE]
		# Keys that we can't remove would come back at every prompt
		rm -f -- $SSH_TYPEAHEAD_FILE || return
		zle -U -- $keys
	}
	_ssh_typeahead_forget() {
		emulate -L zsh
		rm -f -- $SSH_TYPEAHEAD_FILE
	}
	autoload -Uz add-zle-hook-widget add-zsh-hook
	add-zle-hook-widget line-init _ssh_typeahead_push
	add-zsh-hook zshexit _ssh_typeahead_forget
}
