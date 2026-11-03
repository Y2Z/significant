# significant

Sign if I can't. Sign and verify media files in place, with no sidecar files.

    significant sign video.mp4
    significant verify video.mp4
    significant unsign video.mp4
    significant restore video.mp4

`unsign` saves the manifest as `video.mp4.c2pa`. `restore` puts it back if it
still matches the file. The saved manifest identifies the signing device, so
use `unsign --discard` when removing a signature for privacy.

`significant` is a simple wrapper around [C2PA](https://c2pa.org). These formats use
C2PA's standard embedding through the `c2pa` crate:

- Images: PNG, JPEG, HEIC, HEIF, AVIF, WebP, GIF, TIFF, DNG, JPEG XL, SVG
- Video: MP4, M4V, MOV, AVI
- Audio: MP3, M4A, WAV, FLAC

Sony ARW and Nikon NEF files can only be verified. `c2pa` does not write them, so
`sign`, `unsign` and `restore` refuse them. Verification of these files is untested.

`scripts/smoke.sh` tests each format it can generate and reports any it skips.

MKV has no C2PA mapping, so `significant` stores the manifest store as a
Matroska attachment named `significant.c2pa`. Other C2PA tools will not find it.

## Key location

Keys and the trust list live in one folder, which is worth backing up:

- Linux and macOS: `$XDG_CONFIG_HOME/significant`, or `~/.config/significant`
- Windows: `%APPDATA%\significant`

Set `SIGNIFICANT_HOME` to use another folder, or pass `--key-dir` for one command.

## Trust

`verify` always shows the signer's fingerprint. Another key cannot reuse it, but it
only tells you who signed if you know whose it is:

    significant trust sha256:9f3a...     # trust one device
    significant trust newsroom-ca.pem    # trust a certificate authority
    significant verify video.mp4         # identity: trusted
    significant verify --require-trust video.mp4   # fails unless trusted

`sign` prints a device's fingerprint when it creates the key, and `verify` shows it. A PEM file can also be a published list of
trusted authorities. The list lives in the key directory.

Trust is about who signed. Whether the content is intact is checked separately.

## Archives

`significant` also signs ZIP, TAR, `.tar.gz`, `.tgz`, `.tar.xz`, `.txz`, `.tar.zst`
and `.tzst` files. Nothing is unpacked or recompressed.

ZIP stores the manifest as a `META-INF/content_credential.c2pa` entry, the location
C2PA defines, so it extracts as a normal file. It does not yet use C2PA's collection
hash for ZIP, so other C2PA tools may not validate it.

TAR flavors append a small frame after the archive, and `tar` stops before it. This
format is specific to `significant`. Decompressing a `.tar.gz` or `.tar.xz` on its own
keeps the manifest bytes after the end of the TAR data.

Changing, re-zipping or recompressing an archive breaks the signature, even if the
files inside are identical. `.tar.bz2` is not supported yet.

## Manifest location

`significant ranges video.mp4` prints each manifest range as `start length`, and
`significant::manifest_ranges()` returns them in Rust. Hashers can skip those
bytes to get a value that ignores the manifest.

That value is not the hash of the original file, because container bytes around
the manifest remain. The ranges are also read from the file, so verify it before
relying on them. C2PA itself may exclude more bytes than these, and MP4 uses its
own hashing scheme, so other validators should follow the signed manifest.

## Status

Early prototype.

- `sign` creates a key **file** on first use. Losing it means a new identity, so back
  it up. Use `keygen --force` to replace it. This is a development stand-in. The private key
  is not protected the way phone hardware would protect it. Implement `DeviceKey`
  for Android Keystore or the iOS Secure Enclave.
- A signature shows that a key signed the bytes. It does not prove that a camera
  captured them, or who owns the key.
- `identity: unknown` means the signer is not on your trust list.
- Certificate revocation and trusted timestamps are not checked.
- Changing the file breaks the signature. Re-encoding does this, and remuxing an MKV also drops the attachment.
- `unsign` keeps the media, but MP3, FLAC, TIFF-based and SVG files may not return
  byte for byte.
- `restore` does not work on TIFF or DNG, because signing rearranges those files.
  It refuses safely, so keep a signed copy if you need one.
- JPEG XL files must use the container format. Bare codestreams are refused.
- `ranges` reports an error for GIF and SVG, which do not keep a manifest in one block.
- Verification covers the media and the signed claims. Some JUMBF box length
  fields in the manifest are not signed, so a change there is not reported.
- MKV files with an existing Attachments element are refused unless it is last.

## Phone design

This part is a design only. No phone implementation exists yet.

A camera app would create a P-256 key in Android Keystore or the iOS Secure
Enclave, then implement `DeviceKey`. The app returns the certificate chain and
asks the hardware to sign each message, so the private key never leaves it.
Signing happens right after capture, and the rest of the crate is unchanged.

Proving that a real camera made a file needs hardware attestation as well.
A stable device key also lets anyone link files signed by that device, so a
privacy-sensitive app may prefer a new key for each file.

## Test

    cargo test
    cargo build
    scripts/smoke.sh

`examples/mkv_attach.rs` exercises the Matroska layer without C2PA.

## License

`significant` is released under the [BSD Zero Clause License](LICENSE).
Dependencies keep their own licenses.
