//! Build script for `dcg`.
//!
//! Embeds build metadata (timestamp, git commit, rustc version) into the binary
//! for display in --version output and debugging.

use vergen_gix::{Build, Cargo, Emitter, Rustc};

fn main() {
    // Emit build metadata as environment variables at compile time
    let build = Build::builder().build_timestamp(true).build();
    let cargo = Cargo::builder().target_triple(true).build();
    let rustc = Rustc::builder().semver(true).build();

    let mut emitter = Emitter::default();

    // Add build, cargo, and rustc instructions if available
    if let Err(e) = emitter.add_instructions(&build) {
        eprintln!("cargo:warning=vergen build instructions failed: {e}");
    }

    if let Err(e) = emitter.add_instructions(&cargo) {
        eprintln!("cargo:warning=vergen cargo instructions failed: {e}");
    }

    if let Err(e) = emitter.add_instructions(&rustc) {
        eprintln!("cargo:warning=vergen rustc instructions failed: {e}");
    }

    // Emit all collected instructions
    if let Err(e) = emitter.emit() {
        eprintln!("cargo:warning=vergen emit failed: {e}");
    }
}
