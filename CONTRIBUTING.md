# Contributing

Bug reports, small focused patches, documentation and reproducible format samples
are welcome. Please open an issue before proposing a substantial API or format change.

Use public synthetic fixtures where possible. Do not submit private photos,
credentials, personal metadata, or files you are not entitled to redistribute.
Describe the format specification and expected result independently of the implementation.
For parser changes, include malformed/truncated and segmented-input tests as well
as the successful case. Resource-limit and cancellation behavior are part of the API.

Run these checks before opening a pull request:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo test --doc
cargo package
```

The minimum supported Rust version is recorded in Cargo.toml and tested in CI.
Keep new dependencies minimal and discuss them first. Include upstream attribution
and compatible license notices for adapted code or data.

Unless explicitly stated otherwise, contributions submitted for inclusion are
licensed under Apache-2.0, without additional terms. Be respectful, discuss the
code rather than the person, and avoid harassment or sharing personal information.
