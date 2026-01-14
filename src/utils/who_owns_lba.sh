#!/usr/bin/env bash
set -euo pipefail

# Usage: sudo ./who_owns_lba.sh <image.img> <LBA (512B sectors)>

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <image.img> <LBA (512-byte sectors)>" >&2
  exit 1
fi

IMG="$1"
LBA="$2"

if [[ ! -r "$IMG" ]]; then
  echo "Image not readable: $IMG" >&2
  exit 1
fi
if ! [[ "$LBA" =~ ^[0-9]+$ ]]; then
  echo "LBA must be an integer (512-byte sectors)" >&2
  exit 1
fi
if [[ $EUID -ne 0 ]]; then
  echo "Please run as root (sudo)"; exit 1
fi

# tools check
for t in losetup mount umount debugfs dumpe2fs filefrag hexdump dd find awk sed xargs; do
  command -v "$t" >/dev/null 2>&1 || { echo "Missing tool: $t" >&2; exit 1; }
done

MNT="$(mktemp -d -t lba_owner.XXXXXXXX)"
LOOP_DEV=""

cleanup() {
  set +e
  mountpoint -q "$MNT" && umount "$MNT"
  [[ -n "$LOOP_DEV" ]] && losetup -d "$LOOP_DEV" >/dev/null 2>&1
  rmdir "$MNT" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Attach loop with partitions; pick p1 if present
LOOP_DEV="$(losetup -f --show -P "$IMG")"
FS_DEV="$LOOP_DEV"
if [[ -e "${LOOP_DEV}p1" ]]; then
  FS_DEV="${LOOP_DEV}p1"
fi

# Mount ro
mount -o ro,nosuid,nodev,noexec "$FS_DEV" "$MNT"

BYTE_OFF=$(( LBA * 512 ))

FS_BS="$(dumpe2fs -h "$FS_DEV" 2>/dev/null | sed -n 's/^Block size:[[:space:]]*//p' | head -1)"
if ! [[ "$FS_BS" =~ ^[0-9]+$ ]]; then
  echo "Warning: could not parse ext4 block size; defaulting to 4096" >&2
  FS_BS=4096
fi

FSBLK=$(( BYTE_OFF / FS_BS ))
INBLK_OFF=$(( BYTE_OFF % FS_BS ))

echo "== Input =="
echo "Image:        $IMG"
echo "LBA (512B):   $LBA"
echo "Byte offset:  $BYTE_OFF"
echo "Mounted on:   $MNT (via $FS_DEV)"
echo "ext4 blk sz:  $FS_BS"
echo "FS block #:   $FSBLK"
echo "Offset in FS block: $INBLK_OFF"
echo

echo "== ext4 allocation check =="
debugfs -R "testb $FSBLK" "$FS_DEV" || true
echo

echo "== block -> inode(s) (icheck) =="
ICHECK_OUT="$(debugfs -R "icheck $FSBLK" "$FS_DEV" 2>&1 || true)"
echo "$ICHECK_OUT"
INOS="$(awk 'NF==2 && $1+0==$1 {print $2}' <<<"$ICHECK_OUT" || true)"
echo

FOUND_PATHS=0
if [[ -n "$INOS" ]]; then
  echo "== inode -> path (ncheck) =="
  while read -r ino; do
    [[ -z "$ino" ]] && continue
    debugfs -R "ncheck $ino" "$FS_DEV" || true
    FOUND_PATHS=1
  done <<< "$INOS"
  echo
fi

if [[ "$FOUND_PATHS" -eq 0 ]]; then
  echo "== filefrag sweep (fallback) =="
  find "$MNT" -xdev -type f -print0 \
  | xargs -0 -n200 filefrag -e -v 2>/dev/null \
  | awk -v tgt="$FSBLK" '
      BEGIN{file=""}
      /^[[:space:]]*\/.*$/ {file=$0; next}
      /: *[0-9]+: *[0-9]+/ {
        split($0,a,":"); phys=a[3]+0; len=a[4]+0;
        if (tgt>=phys && tgt<phys+len) { print "owns FS block: " file }
      }'
  echo
fi

echo "== 4KiB view at LBA =="
dd if="$IMG" bs=512 skip="$LBA" count=8 status=none | hexdump -C | sed -n '1,32p'
echo

if [[ -n "$INOS" ]]; then
  echo "== file-relative offset (best effort) =="
  while read -r ino; do
    [[ -z "$ino" ]] && continue
    debugfs -R "ncheck $ino" "$FS_DEV" 2>/dev/null \
      | awk 'NR>1{print $2}' \
      | while read -r p; do
          [[ -z "$p" ]] && continue
          filefrag -e -v "$p" 2>/dev/null \
          | awk -v tgt="$FSBLK" -v bs="$FS_BS" -v off_in="$INBLK_OFF" -v path="$p" '
              /^ *[0-9]+: +[0-9]+\.\.[0-9]+: +[0-9]+/ {
                split($0,a,":");
                log=a[2]; sub(/^[[:space:]]*/,"",log); split(log,lr,".."); l0=lr[1]+0;
                phy=a[3]; sub(/^[[:space:]]*/,"",phy); split(phy,pr,".."); p0=pr[1]+0;
                len=a[4]+0;
                if (tgt>=p0 && tgt<p0+len) {
                  byte_off = l0*bs + ((tgt-p0)*bs + off_in);
                  printf("File: %s  byte_offset=%d\n", path, byte_off);
                }
              }'
        done
  done <<< "$INOS"
  echo
fi

echo "Done."
