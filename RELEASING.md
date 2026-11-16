# Releasing

1. Run the documented tests, Clippy, formatting, documentation and packaging checks
   on the exact revision to release. Confirm minimum-Rust and platform CI is green.
2. Review Cargo.toml, README, CHANGELOG, LICENSE, NOTICE and source provenance.
   Inspect `cargo package --list` and the unpacked archive for omitted resources,
   private files or build artifacts. Run `cargo publish --dry-run --locked`.
3. Update the version and changelog, commit, then tag the validated revision with
   `v<version>` and create release notes describing coverage and known limits.
4. The owner publishes to crates.io with an appropriately scoped token or approved
   trusted-publishing configuration. Never put registry credentials in files or logs.
5. Verify the registry package and docs.rs output. Only then replace Git-install
   instructions with registry-version instructions.

A GitHub tag alone does not mean a crate has been uploaded to crates.io. This
repository intentionally contains no automatic registry-upload workflow.
