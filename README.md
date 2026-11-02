# significant

Sign if I can't. Sign and verify media files in place, with no sidecar files.

    significant keygen
    significant sign video.mp4
    significant verify video.mp4
    significant unsign video.mp4
    significant restore video.mp4

`unsign` saves the manifest as `video.mp4.c2pa`. `restore` puts it back if it
still matches the file. The saved manifest identifies the signing device, so
use `unsign --discard` when removing a signature for privacy.

`significant` is a simple wrapper around [C2PA](https://c2pa.org). PNG, JPEG, MP4,
MOV, M4A, MP3 and WAV use C2PA's standard embedding through the `c2pa` crate.

MKV has no C2PA mapping, so `significant` stores the manifest store as a
Matroska attachment named `significant.c2pa`. Other C2PA tools will not find it.

## Status

Early prototype.

- `keygen` creates a key **file**. This is a development stand-in. The private key
  is not protected the way phone hardware would protect it. Implement `DeviceKey`
  for Android Keystore or the iOS Secure Enclave.
- A signature shows that a key signed the bytes. It does not prove that a camera
  captured them, or who owns the key.
- `identity: not checked` is expected, because device keys are self-issued.
- Changing the file breaks the signature. Re-encoding does this, and remuxing an MKV also drops the attachment.
- `unsign` restores the media, but MP3 files may not return byte for byte.
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
