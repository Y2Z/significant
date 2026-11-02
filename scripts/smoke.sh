#!/usr/bin/env bash
# End-to-end check. Needs ffmpeg. Run from the repo root.
set -u
BIN="$PWD/target/debug/significant"
WORK=$(mktemp -d)
export SIGNIFICANT_HOME="$WORK/keys"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
fail=0
check() {
  if out=$("${@:2}" 2>&1); then echo "ok    $1"; return 0; fi
  echo "FAIL  $1"; printf '%s\n' "$out" | sed 's/^/      /'; fail=1; return 1
}
refuse() {
  if out=$("${@:2}" 2>&1); then echo "FAIL  $1"; fail=1; else echo "ok    $1"; printf '%s\n' "$out" | sed 's/^/      /'; fi
}

# MD5 of the decoded audio and video.
decoded() { ffmpeg -v error -i "$1" -map 0 -f md5 - 2>/dev/null; }

# Flips one byte of original media, located inside the signed copy.
tamper() {
  python3 - "$1" "$2" <<'PY'
import sys
original = open(sys.argv[1], "rb").read()
signed = bytearray(open(sys.argv[2], "rb").read())
at = len(original) * 3 // 4
offset = signed.find(original[at:at + 32])
if offset < 0:
    sys.exit(1)
offset += 16
signed[offset] ^= 0xFF
open(sys.argv[2], "wb").write(signed)
print(f"      flipped media byte at offset {offset} of {len(signed)}")
PY
}

# The reported ranges, joined, must equal the saved manifest.
ranges_hold_manifest() {
  "$BIN" ranges "$1" | python3 -c '
import sys
data, store = open(sys.argv[1], "rb").read(), open(sys.argv[2], "rb").read()
spans = [tuple(map(int, line.split())) for line in sys.stdin]
held = b"".join(data[start:start + length] for start, length in spans)
sys.exit(not spans or held != store)
' "$1" "$2"
}

# Flips every byte of the manifest outside long zero runs, one at a time.
attack_manifest() {
  python3 - "$BIN" "$1" "$2" <<'PY'
import concurrent.futures, itertools, os, subprocess, sys
binary, signed_path, store_path = sys.argv[1:4]
signed, store = open(signed_path, "rb").read(), open(store_path, "rb").read()
start = signed.find(store)
if start < 0:
    print("      manifest bytes not found in signed file")
    sys.exit(1)

positions, skipped, offset = [], 0, 0
for byte, run in itertools.groupby(store):
    length = len(list(run))
    if byte == 0 and length >= 32:
        skipped += length
    else:
        positions.extend(range(offset, offset + length))
    offset += length

def undetected(position):
    data = bytearray(signed)
    data[start + position] ^= 0xFF
    path = f"flip{position}-{signed_path}"
    with open(path, "wb") as file:
        file.write(data)
    result = subprocess.run([binary, "verify", path], capture_output=True)
    os.remove(path)
    return result.returncode == 0

with concurrent.futures.ThreadPoolExecutor(os.cpu_count()) as pool:
    missed = [p for p, bad in zip(positions, pool.map(undetected, positions)) if bad]
print(f"      store {len(store)} bytes: {len(positions) - len(missed)} of {len(positions)} flips detected, "
      f"{skipped} zero-run bytes skipped")

def boxes(data, start, end, parent):
    """Yields (offset, box name) for every JUMBF box in a range."""
    position = start
    while position + 8 <= end:
        length = int.from_bytes(data[position:position + 4], "big")
        kind = data[position + 4:position + 8]
        if length < 8 or position + length > end:
            return
        name = f"{parent}/{kind.decode('latin-1')}"
        if kind == b"jumb":
            label = data[position + 33:position + 96].split(b"\0")[0]
            name = f"{parent}/{label.decode('latin-1')}"
            yield position, name
            yield from boxes(data, position + 8, position + length, name)
        else:
            yield position, name
        position += length

def report(path):
    return subprocess.run([binary, "verify", "--json", path], capture_output=True, text=True)

framing = {offset + i: name for offset, name in boxes(store, 0, len(store), "") for i in range(4)}
expected = report(signed_path).stdout
failed = False
for position in missed:
    data = bytearray(signed)
    data[start + position] ^= 0xFF
    path = f"flip{position}-{signed_path}"
    with open(path, "wb") as file:
        file.write(data)
    result = report(path)
    os.remove(path)
    is_framing = position in framing
    same = result.returncode == 0 and result.stdout == expected
    failed = failed or not (is_framing and same)
    where = f"length of {framing[position]}" if is_framing else "NOT a box length"
    print(f"      offset {position}: {where}, report {'identical' if same else 'DIFFERENT'}")
sys.exit(1 if failed else 0)
PY
}

# Reads a file with the separate c2patool program.
third_party() {
  c2patool "$1" 2>&1 | python3 -c '
import json, sys
text = sys.stdin.read()
report = json.loads(text[text.index("{"):])
state = report.get("validation_state", "missing")
failures = report.get("validation_results", {}).get("activeManifest", {}).get("failure", [])
codes = [item.get("code") for item in failures]
print(f"      c2patool state {state}, failures {codes}")
sys.exit(state == "Invalid" or any(code != "signingCredential.untrusted" for code in codes))
'
}

ffmpeg -v error -f lavfi -i testsrc=d=2:s=320x240:r=30 -f lavfi -i sine=d=2 -c:v libx264 -c:a aac -pix_fmt yuv420p a.mp4
ffmpeg -v error -f lavfi -i testsrc=d=2:s=320x240:r=30 -f lavfi -i sine=d=2 -c:v libx264 -c:a aac a.mkv
ffmpeg -v error -f lavfi -i testsrc=s=320x240 -frames:v 1 a.png
ffmpeg -v error -f lavfi -i testsrc=s=320x240 -frames:v 1 a.jpg
ffmpeg -v error -f lavfi -i sine=d=2 -c:a libmp3lame a.mp3

mkdir tree tree/sub
echo hello > tree/a.txt
head -c 30000 /dev/urandom > tree/b.bin
echo nested > tree/sub/c.txt
zip -qr a.zip tree
tar cf a.tar tree
gzip -c a.tar > a.tar.gz
gzip -c a.tar > a.tgz
xz -c a.tar > a.tar.xz
archives="a.zip a.tar a.tar.gz a.tgz a.tar.xz"
if command -v zstd >/dev/null; then
  zstd -q -c a.tar > a.tar.zst
  archives="$archives a.tar.zst"
else
  echo "skip  zstd not installed"
fi

# Lists an archive's names and checks that it extracts to the original tree.
archive_tools_ok() {
  rm -rf extracted && mkdir extracted
  case "$1" in
    *.zip) unzip -tq "$1" >/dev/null && unzip -qo "$1" -d extracted || return 1
           rm -rf extracted/META-INF ;;
    *) tar xf "$1" -C extracted || return 1 ;;
  esac
  diff -r tree extracted/tree
}

"$BIN" keygen
for f in a.png a.jpg a.mp4 a.mp3 a.mkv; do
  echo "--- $f"
  original=$(sha256sum < "$f")
  cp "$f" "orig-$f"
  media=$(decoded "$f")
  if ! check "sign $f" "$BIN" sign "$f"; then echo "skip  remaining $f checks"; continue; fi
  check  "verify $f" "$BIN" verify "$f"
  "$BIN" verify "$f" | sed 's/^/      /'
  check  "decodes $f" ffmpeg -v error -i "$f" -f null -
  refuse "double sign refused $f" "$BIN" sign "$f"
  check  "signing keeps media $f" test "$(decoded "$f")" = "$media"
  cp "$f" "tamper-$f"
  if ! tamper "orig-$f" "tamper-$f"; then echo "FAIL  could not find media bytes in $f"; fail=1; continue; fi
  refuse "tampered file fails $f" "$BIN" verify "tamper-$f"
  signed=$(sha256sum < "$f")
  cp "$f" "signed-$f"
  check  "unsign $f" "$BIN" unsign "$f"
  check  "manifest saved $f" test -s "$f.c2pa"
  check  "ranges hold manifest $f" ranges_hold_manifest "signed-$f" "$f.c2pa"
  refuse "ranges report unsigned $f" "$BIN" ranges "$f"
  refuse "unsigned after unsign $f" "$BIN" verify "$f"
  check  "unsign keeps media $f" test "$(decoded "$f")" = "$media"
  if [ "$(sha256sum < "$f")" = "$original" ]; then echo "ok    byte-identical $f"
  else echo "note  not byte-identical $f"; fi
  unsigned=$(sha256sum < "$f")
  cp "$f" "wrong-$f"
  printf '\xff' | dd of="wrong-$f" bs=1 seek=$(($(stat -c%s "wrong-$f") * 3 / 4)) conv=notrunc status=none
  wrong=$(sha256sum < "wrong-$f")
  refuse "restore refused on changed file $f" "$BIN" restore "wrong-$f" "$f.c2pa"
  check  "refused restore left file alone $f" test "$(sha256sum < "wrong-$f")" = "$wrong"
  if check "restore $f" "$BIN" restore "$f"; then
    check "verify after restore $f" "$BIN" verify "$f"
    check "restore keeps media $f" test "$(decoded "$f")" = "$media"
    if [ "$(sha256sum < "$f")" = "$signed" ]; then echo "ok    restored byte-identical $f"
    else echo "note  restored file differs from signed $f"; fi
    refuse "saved manifest protected $f" "$BIN" unsign "$f"
    check  "refused unsign left file signed $f" "$BIN" verify "$f"
    check  "unsign --force $f" "$BIN" unsign --force "$f"
    check  "restore again $f" "$BIN" restore "$f"
    rm -f "$f.c2pa"
    check  "unsign --discard $f" "$BIN" unsign --discard "$f"
    refuse "discard saves nothing $f" test -e "$f.c2pa"
  fi
done

for f in $archives; do
  echo "--- $f"
  original=$(sha256sum < "$f")
  cp "$f" "orig-$f"
  if ! check "sign $f" "$BIN" sign "$f"; then echo "skip  remaining $f checks"; continue; fi
  check  "verify $f" "$BIN" verify "$f"
  "$BIN" verify "$f" | sed 's/^/      /'
  check  "tools accept signed $f" archive_tools_ok "$f"
  refuse "double sign refused $f" "$BIN" sign "$f"
  cp "$f" "tamper-$f"
  if tamper "orig-$f" "tamper-$f"; then refuse "tampered file fails $f" "$BIN" verify "tamper-$f"
  else echo "FAIL  could not find archive bytes in $f"; fail=1; fi
  signed=$(sha256sum < "$f")
  cp "$f" "signed-$f"
  check  "unsign $f" "$BIN" unsign "$f"
  check  "ranges hold manifest $f" ranges_hold_manifest "signed-$f" "$f.c2pa"
  check  "byte-identical $f" test "$(sha256sum < "$f")" = "$original"
  check  "restore $f" "$BIN" restore "$f"
  check  "verify after restore $f" "$BIN" verify "$f"
  check  "restored byte-identical $f" test "$(sha256sum < "$f")" = "$signed"
done

echo "--- attacks"
for f in a.png a.jpg a.mp4 a.mp3 a.mkv $archives; do
  target="attack-$f"
  cp "orig-$f" "$target"
  "$BIN" sign "$target" >/dev/null || { echo "FAIL  sign $target"; fail=1; continue; }
  cp "$target" "held-$f"
  if command -v c2patool >/dev/null && [[ " a.png a.jpg a.mp4 a.mp3 " == *" $f "* ]]; then
    if third_party "$target"; then echo "ok    c2patool accepts $f"; else echo "FAIL  c2patool rejects $f"; fail=1; fi
  elif ! command -v c2patool >/dev/null; then
    echo "skip  c2patool not installed"
  fi
  "$BIN" unsign "$target" >/dev/null
  if attack_manifest "held-$f" "$target.c2pa"; then echo "ok    manifest flips $f"
  else echo "FAIL  manifest flips $f"; fail=1; fi
done
exit $fail
