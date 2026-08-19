//! Build script for `dcg`.
//!
//! Embeds build metadata (timestamp, git commit, rustc version) into the binary
//! for display in --version output and debugging.

use vergen_gix::{Build, Cargo, Emitter, Gix, Rustc};

fn main() {
    // Emit build metadata as environment variables at compile time
    let build = Build::builder().build_timestamp(true).build();
    let cargo = Cargo::builder().target_triple(true).build();
    let rustc = Rustc::builder().semver(true).build();
    // Git provenance (#320): `git describe --tags --dirty` distinguishes a
    // build made exactly at a release tag (`v1.2.3`) from a local build ahead
    // of it (`v1.2.3-7-gabc1234`, or a `-dirty` suffix). Outside a git
    // checkout (crates.io tarball, `cargo install` from a registry) these
    // variables are absent or hold vergen's idempotent placeholder, and the
    // runtime treats provenance as unknown.
    let gix = Gix::builder()
        .describe(true, true, None)
        .sha(true)
        .dirty(false)
        .build();

    // Make the explicit release-channel marker (#320) rebuild-aware: release
    // pipelines (dist.yml, DSR) export DCG_RELEASE_BUILD=1 so the binary can
    // prove it was produced by a release pipeline rather than a dev checkout.
    println!("cargo:rerun-if-env-changed=DCG_RELEASE_BUILD");

    let mut emitter = Emitter::default();

    // Add build, cargo, rustc, and git instructions if available
    if let Err(e) = emitter.add_instructions(&build) {
        eprintln!("cargo:warning=vergen build instructions failed: {e}");
    }

    if let Err(e) = emitter.add_instructions(&cargo) {
        eprintln!("cargo:warning=vergen cargo instructions failed: {e}");
    }

    if let Err(e) = emitter.add_instructions(&rustc) {
        eprintln!("cargo:warning=vergen rustc instructions failed: {e}");
    }

    if let Err(e) = emitter.add_instructions(&gix) {
        eprintln!("cargo:warning=vergen git instructions failed: {e}");
    }

    // Emit all collected instructions
    if let Err(e) = emitter.emit() {
        eprintln!("cargo:warning=vergen emit failed: {e}");
    }
}
