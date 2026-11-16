# Releasing

1. Run the documented tests, Clippy, formatting, documentation and packaging checks
   on the exact revision to release. Confirm minimum-Rust and platform CI is green.
2. Review Cargo.toml, README, CHANGELOG, LICENSE, NOTICE and source provenance.
   Inspect `cargo package --list` and the unpacked archive for omitted resources,
   private files or build artifacts. Run `cargo publish --dry-run --locked`.
3. Update the version and changelog, commit, then tag the validated revision with
   `v<version>` and create release notes describing coverage and known limits.
4. Configure the repository Actions secret `CRATES_IO_TOKEN` with a crates.io token
   permitted to publish this crate. Publishing runs when a GitHub release is
   published, or manually through the **Publish** workflow with an existing tag.
   It checks identity/version, reruns validation, and maps the secret to Cargo's
   `CARGO_REGISTRY_TOKEN` only in the credential check and publishing steps.
   A missing credential is an explicit failure, not a skipped successful release.
5. Verify the registry package and docs.rs output. Only then replace Git-install
   instructions with registry-version instructions.

A GitHub tag alone does not mean a crate has been uploaded to crates.io. Existing
releases made before this workflow was added can use its manual tag input. Never
put registry credentials in source, logs, command-line token arguments or artifacts.
Version uploads are immutable; rerunning an already published version fails rather
than silently assuming it contains the same code.
