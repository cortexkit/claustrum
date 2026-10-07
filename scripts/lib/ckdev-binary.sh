# Link artifacts into caller-owned scratch space before executing them. Keep
# production/staged names intact, and preserve macOS's signed inode when possible.
ckdev_binary() {
  local src="$1" scratch="$2" name dir dst
  name="${src##*/}"
  name="${name#ck-}"
  name="${name#ckdev-}"
  dir="$(mktemp -d "$scratch/ckdev-bin.XXXXXX")" || return
  dst="$dir/ckdev-$name"
  ln "$src" "$dst" 2>/dev/null || cp "$src" "$dst" || return
  printf '%s\n' "$dst"
}
