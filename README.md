# mime-rs

Fast, bounded file-signature detection in Rust. The crate is **`mime-inspect`**;
the repository name is `mime-rs` because the `mime-rs` crate name is already in use.

`mime-inspect` recognizes selected common binary formats and supports a small,
explicit magic-rule grammar. Matching borrows immutable rules and does not allocate,
open files, decompress content or start background work. Unknown input and an empty
input have distinct results.

## Use

The initial version is available from Git; it has not been published to crates.io:

```toml
[dependencies]
mime-inspect = { git = "https://github.com/jcalcote/mime-rs", tag = "v0.1.0" }
```

```rust
use mime_inspect::{Classification, Detector};

let detector = Detector::new();
match detector.detect(b"\x89PNG\r\n\x1a\n") {
    Classification::Match(found) => println!("{:?}", found.mime),
    Classification::Empty => println!("empty input"),
    Classification::Unknown => println!("unknown format"),
}
```

Results borrow the detector rather than the inspected bytes. `detect_segments`
accepts borrowed byte slices when input is scattered. Classification examines a
prefix of at most 128 bytes; supply enough bytes for the signatures you need.
An unknown result is an absence of evidence, not a text-file assertion.

## Custom rules

Rules are parsed once with `Detector::with_rules`. Invalid, unsupported or oversized
rules return a structural error; the caller decides whether to fall back.
There is no implicit filename, global rule configuration or silent file fallback.

The initial grammar supports absolute offsets, escaped strings/spaces, equality,
byte and explicit little/big-endian 16/32-bit comparisons, numeric masks, MIME
annotations and required single-level continuations. Rule text is limited to
64 KiB, 256 groups and 1,024 checks. Relative/indirect offsets, search, regex,
nested/optional continuations and the full libmagic language are not supported.
See the public examples and source-level API documentation for accepted syntax.

Compression hints are advisory format properties. They do not dictate an
application's compression policy or promise that compression will save space.
Classification is not malware detection, format validation or a security boundary.
Do not use a filename or reported MIME type alone to trust an untrusted file.

## Scope and resource behavior

The catalog is intentionally finite. Supported signatures, custom-rule boundaries,
segmentation and malformed inputs have synthetic regression tests. The library
does not claim universal MIME coverage or full compatibility with any magic VM.
Rule compilation allocates retained immutable state; matching allocates no heap.
Documented planning helpers report requested storage rather than process RSS or
allocator-specific accounting.

Minimum supported Rust: **1.85**, edition 2024. There are no runtime dependencies.
CI runs tests on Linux, macOS and Windows, checks the minimum Rust version, builds
documentation and verifies the crates.io package. See [CONTRIBUTING.md](CONTRIBUTING.md)
for local checks and fixture requirements.

## License and attribution

Rust code is Apache-2.0; selected signature data also retains ISC terms. See
[LICENSE](LICENSE) and [NOTICE](NOTICE). Selected signature data and
behavior derive from [simplemagic](https://github.com/j256/simplemagic) under its
retained ISC notice. New rules and bug reports are welcome.
