#!/usr/bin/env bash
# Linux disk imaging wrapper (guide 9.3, docs/collection.md): ewfacquire, else dc3dd, else dd.
#
#   sudo ./acquire-disk-linux.sh --source /dev/sdb --output /mnt/evidence/case1
#        [--tool ewfacquire|dc3dd|dd] [--case-ref IR-1] [--evidence-number EV-004]
#        [--operator alice] [--description "suspect laptop SSD"]
#
# Use a hardware write blocker for physical media. This script only READS the source device (it
# never mounts it, never calls blockdev --setro or any other state change) and NEVER downloads a
# tool: install libewf-tools / dc3dd from your distribution or forensic media beforehand.
#
# Writes disk_<device>_<UTC>.{E01|dd} (+ .sha256, .acquisition.json, tool log) into --output.
# Exit codes: 0 ok, 2 tool missing / bad arguments / unsafe target, 3 not root, 5 failed.
set -euo pipefail

VERSION="1.0.0"
SOURCE="" OUTPUT="" TOOL="" CASE_REF="" EVNUM="" OPERATOR="" DESCRIPTION=""

die() { echo "error: $2" >&2; exit "$1"; }
json() {
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
    --source) SOURCE=${2-}; shift 2 ;;
    --output) OUTPUT=${2-}; shift 2 ;;
    --tool) TOOL=${2-}; shift 2 ;;
    --case-ref) CASE_REF=${2-}; shift 2 ;;
    --evidence-number) EVNUM=${2-}; shift 2 ;;
    --operator) OPERATOR=${2-}; shift 2 ;;
    --description) DESCRIPTION=${2-}; shift 2 ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) die 2 "unknown argument: $1" ;;
  esac
done
[[ -n "$SOURCE" && -n "$OUTPUT" ]] || die 2 "--source and --output are required"

# ---- tool: never downloaded; the first available one unless --tool names it.
if [[ -z "$TOOL" ]]; then
  for candidate in ewfacquire dc3dd dd; do
    if command -v "$candidate" >/dev/null 2>&1; then TOOL=$candidate; break; fi
  done
fi
case "$TOOL" in
  ewfacquire|dc3dd|dd) ;;
  "") die 2 "no imaging tool found (ewfacquire, dc3dd or dd); install one from trusted media" ;;
  *) die 2 "unsupported --tool $TOOL (ewfacquire|dc3dd|dd)" ;;
esac
TOOL_PATH=$(command -v "$TOOL" || true)
[[ -n "$TOOL_PATH" ]] || die 2 "$TOOL not found in PATH. This wrapper does not download tools."
[[ "${EUID:-$(id -u)}" -eq 0 ]] || die 3 "disk imaging needs root."
[[ -b "$SOURCE" ]] || die 2 "$SOURCE is not a block device"

mkdir -p -- "$OUTPUT"
OUTPUT=$(cd -- "$OUTPUT" && pwd)
# Refuse to write the image onto the device being imaged (or one of its partitions).
out_dev=$(df -P -- "$OUTPUT" | awk 'NR == 2 {print $1}')
src_name=$(basename -- "$(readlink -f -- "$SOURCE")")
out_parent=$(lsblk -no PKNAME -- "$out_dev" 2>/dev/null | head -n 1 || true)
if [[ "$(basename -- "$out_dev")" == "$src_name" || "$out_parent" == "$src_name" ]]; then
  die 2 "--output is on the source device $SOURCE; write the image to other media"
fi
if findmnt -rn -S "$SOURCE" >/dev/null 2>&1 || lsblk -nro MOUNTPOINT -- "$SOURCE" | grep -q .; then
  echo "warning: $SOURCE (or a partition) is mounted; the image of a live file system may be inconsistent" >&2
fi

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
BASE="$OUTPUT/disk_${src_name//[^A-Za-z0-9._-]/_}_${STAMP}"
[[ ! -e "$BASE.dd" && ! -e "$BASE.E01" ]] || die 2 "$BASE already exists; refusing to overwrite"
SIZE=$(blockdev --getsize64 -- "$SOURCE" 2>/dev/null || echo 0)
MODEL=$(lsblk -dno MODEL -- "$SOURCE" 2>/dev/null | sed 's/ *$//' || true)
SERIAL=$(lsblk -dno SERIAL -- "$SOURCE" 2>/dev/null | sed 's/ *$//' || true)
TOOL_SHA=$(sha256sum -- "$TOOL_PATH" | awk '{print $1}')
EXAMINER=${OPERATOR:-${SUDO_USER:-$(id -un)}}
echo "source:  $SOURCE  model=$MODEL serial=$SERIAL size=$SIZE"
echo "tool:    $TOOL_PATH ($TOOL_SHA)"

STARTED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
set +e
case "$TOOL" in
  ewfacquire)
    IMAGE="$BASE.E01"
    ewfacquire -u -t "$BASE" -f encase6 -c deflate:fast -d sha256 \
      -C "${CASE_REF:-none}" -E "${EVNUM:-none}" -e "$EXAMINER" -D "${DESCRIPTION:-$SOURCE}" \
      -N "serial=$SERIAL model=$MODEL" -l "$BASE.ewfacquire.log" -- "$SOURCE"
    RC=$? ;;
  dc3dd)
    IMAGE="$BASE.dd"
    dc3dd if="$SOURCE" hof="$IMAGE" hash=sha256 log="$BASE.dc3dd.log"
    RC=$? ;;
  dd)
    IMAGE="$BASE.dd"
    dd if="$SOURCE" of="$IMAGE" bs=4M conv=noerror,sync status=progress 2> "$BASE.dd.log"
    RC=$? ;;
esac
set -e
FINISHED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
[[ -f "$IMAGE" ]] || die 5 "$TOOL did not produce an image (exit code $RC)"

IMAGE_SHA=$(sha256sum -- "$IMAGE" | awk '{print $1}')
IMAGE_SIZE=$(stat -c %s -- "$IMAGE")
SOURCE_SHA=""
if [[ "$TOOL" == "dd" ]]; then
  # dd does not verify: hash the source again (read-only) so the image can be compared with it.
  SOURCE_SHA=$(sha256sum -- "$SOURCE" | awk '{print $1}')
  [[ "$SOURCE_SHA" == "$IMAGE_SHA" ]] || echo "warning: image and source hashes differ (read errors are zero-padded by conv=noerror,sync)" >&2
fi
printf '%s  %s\n' "$IMAGE_SHA" "$(basename -- "$IMAGE")" > "$IMAGE.sha256"
{
  printf '{\n "schema": "dfirbench.acquisition/1",\n "kind": "disk_image",\n'
  printf ' "wrapper": {"name": "acquire-disk-linux", "version": %s},\n' "$(json "$VERSION")"
  printf ' "tool": {"name": %s, "path": %s, "sha256": %s, "exit_code": %s},\n' \
    "$(json "$TOOL")" "$(json "$TOOL_PATH")" "$(json "$TOOL_SHA")" "$RC"
  printf ' "source": {"device": %s, "model": %s, "serial": %s, "size": %s, "sha256": %s},\n' \
    "$(json "$SOURCE")" "$(json "$MODEL")" "$(json "$SERIAL")" "${SIZE:-0}" "$(json "$SOURCE_SHA")"
  printf ' "operator": %s,\n "case_ref": %s,\n "evidence_number": %s,\n' \
    "$(json "$EXAMINER")" "$(json "$CASE_REF")" "$(json "$EVNUM")"
  printf ' "started_at": %s,\n "finished_at": %s,\n' "$(json "$STARTED")" "$(json "$FINISHED")"
  printf ' "image": {"file": %s, "size": %s, "sha256": %s}\n}\n' \
    "$(json "$(basename -- "$IMAGE")")" "$IMAGE_SIZE" "$(json "$IMAGE_SHA")"
} > "$IMAGE.acquisition.json"

echo "image:   $IMAGE"
echo "sha256:  $IMAGE_SHA"
[[ "$TOOL" == "ewfacquire" ]] && echo "E01 segments: $BASE.E0?; verify them with ewfverify before upload."
echo 'Upload it as evidence kind "disk_image" with expected_sha256 set to the hash above.'
