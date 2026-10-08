# Copy artifacts into caller-owned scratch space before executing them, under a
# development name, leaving production/staged names intact. Always a COPY, never a
# hard link: on a loaded macOS host a fresh hard link to a cargo binary was
# SIGKILLed at exec (signal 9, empty stderr) while copies were not. The ad-hoc
# signature lives in the file, so the copy still runs.
ckdev_binary() {
  local src="$1" scratch="$2" name dir dst
  name="${src##*/}"
  name="${name#ck-}"
  name="${name#ckdev-}"
  dir="$(mktemp -d "$scratch/ckdev-bin.XXXXXX")" || return
  dst="$dir/ckdev-$name"
  cp -p "$src" "$dst" || return
  printf '%s\n' "$dst"
}
