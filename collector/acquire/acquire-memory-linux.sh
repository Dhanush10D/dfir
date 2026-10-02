#!/usr/bin/env bash
# Linux memory acquisition wrapper around AVML (guide 9.3, docs/collection.md).
#
#   sudo ./acquire-memory-linux.sh --output /mnt/usb/mem [--avml /mnt/usb/tools/avml]
#                                  [--compress] [--case-ref IR-1] [--operator alice]
#
# This script NEVER downloads anything. Obtain AVML (a static binary) from its official release
# page, verify the release hash, copy it to the collection media and pass --avml (or put it next
# to this script or in PATH). LiME needs a kernel-matched module: see docs/collection.md.
#
# Writes mem_<host>_<UTC>.lime (+ .sha256 and .acquisition.json) into --output and nothing else.
# Exit codes: 0 ok, 2 tool missing / bad arguments, 3 not root, 4 not enough space, 5 failed.
set -euo pipefail

VERSION="1.0.0"
OUTPUT="" AVML="" COMPRESS=0 CASE_REF="" OPERATOR=""

die() { echo "error: $2" >&2; exit "$1"; }
json() {  # JSON string literal (escapes backslash, quote and control characters)
  local s=${1-} out="" c i
  for ((i = 0; i < ${#s}; i++)); do
    c=${s:i:1}
    case "$c" in
      '"') out+='\"' ;; '\') out+='\\' ;;
      $'\n') out+='\n' ;; $'\r') out+='\r' ;; $'\t') out+='\t' ;;
      *) if [[ "$c" < " " ]]; then printf -v c '\\u%04x' "'$c"; fi; out+="$c" ;;
    esac
  done
  printf '"%s"' "$out"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) OUTPUT=${2-}; shift 2 ;;
    --avml) AVML=${2-}; shift 2 ;;
    --compress) COMPRESS=1; shift ;;
    --case-ref) CASE_REF=${2-}; shift 2 ;;
    --operator) OPERATOR=${2-}; shift 2 ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) die 2 "unknown argument: $1" ;;
  esac
done
[[ -n "$OUTPUT" ]] || die 2 "--output is required"

# ---- tool: explicit path, else next to this script, else PATH. Never downloaded.
if [[ -z "$AVML" ]]; then
  here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
  if [[ -x "$here/avml" ]]; then AVML="$here/avml"; else AVML=$(command -v avml || true); fi
fi
if [[ -z "$AVML" || ! -f "$AVML" || ! -x "$AVML" ]]; then
  die 2 "AVML not found. This wrapper does not download tools: obtain AVML from its official release page, verify it, and pass --avml PATH."
fi
[[ "${EUID:-$(id -u)}" -eq 0 ]] || die 3 "memory acquisition needs root."

mkdir -p -- "$OUTPUT"
OUTPUT=$(cd -- "$OUTPUT" && pwd)
HOST=$(hostname 2>/dev/null || echo host)
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
IMAGE="$OUTPUT/mem_${HOST//[^A-Za-z0-9._-]/_}_${STAMP}.lime"
[[ ! -e "$IMAGE" ]] || die 2 "$IMAGE already exists; refusing to overwrite"

mem_kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
free_kb=$(df -Pk -- "$OUTPUT" | awk 'NR == 2 {print $4}')
if (( COMPRESS == 0 && free_kb < mem_kb + 524288 )); then
  die 4 "not enough free space in $OUTPUT (need about $(( (mem_kb + 524288) / 1048576 + 1 )) GB)"
fi

TOOL_SHA=$(sha256sum -- "$AVML" | awk '{print $1}')
TOOL_VERSION=$("$AVML" --version 2>/dev/null | head -n 1 || true)
echo "tool:    $AVML ($TOOL_VERSION)"
echo "sha256:  $TOOL_SHA"

STARTED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
args=()
(( COMPRESS == 1 )) && args+=(--compress)
set +e
"$AVML" "${args[@]}" "$IMAGE"
RC=$?
set -e
FINISHED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
[[ -f "$IMAGE" ]] || die 5 "AVML did not produce an image (exit code $RC)"

IMAGE_SHA=$(sha256sum -- "$IMAGE" | awk '{print $1}')
IMAGE_SIZE=$(stat -c %s -- "$IMAGE")
printf '%s  %s\n' "$IMAGE_SHA" "$(basename -- "$IMAGE")" > "$IMAGE.sha256"
{
  printf '{\n "schema": "dfirbench.acquisition/1",\n "kind": "memory",\n'
  printf ' "wrapper": {"name": "acquire-memory-linux", "version": %s},\n' "$(json "$VERSION")"
  printf ' "tool": {"path": %s, "sha256": %s, "version": %s, "exit_code": %s},\n' \
    "$(json "$AVML")" "$(json "$TOOL_SHA")" "$(json "$TOOL_VERSION")" "$RC"
  printf ' "host": {"hostname": %s, "kernel": %s, "mem_total_kb": %s},\n' \
    "$(json "$HOST")" "$(json "$(uname -r)")" "$mem_kb"
  printf ' "operator": %s,\n "case_ref": %s,\n' \
    "$(json "${OPERATOR:-${SUDO_USER:-$(id -un)}}")" "$(json "$CASE_REF")"
  printf ' "started_at": %s,\n "finished_at": %s,\n' "$(json "$STARTED")" "$(json "$FINISHED")"
  printf ' "complete": %s,\n' "$([[ $RC == 0 ]] && echo true || echo false)"
  printf ' "image": {"file": %s, "size": %s, "sha256": %s, "compressed": %s}\n}\n' \
    "$(json "$(basename -- "$IMAGE")")" "$IMAGE_SIZE" "$(json "$IMAGE_SHA")" \
    "$([[ $COMPRESS == 1 ]] && echo true || echo false)"
} > "$IMAGE.acquisition.json"

echo "image:   $IMAGE"
echo "sha256:  $IMAGE_SHA"
(( RC == 0 )) || die 5 "AVML exited with code $RC: the image may be partial (kept, marked \"complete\": false)"
echo 'Upload it as evidence kind "memory" with expected_sha256 set to the hash above.'
