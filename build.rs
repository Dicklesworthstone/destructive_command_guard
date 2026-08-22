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

    embed_windows_resources();
}

/// Embed a VERSIONINFO resource and an application manifest into the Windows
/// PE (#303).
///
/// `dcg.exe` shipped with no version resource at all — empty FileVersion,
/// CompanyName, FileDescription — while also being unsigned, stripped, and
/// size-optimized. That combination is close to a worst-case input for
/// Defender's `!ml` heuristics and leaves the binary anonymous in Explorer,
/// Task Manager, and AV vendor submissions. The resource is metadata only: it
/// changes no code path.
///
/// The manifest declares `asInvoker` (dcg never needs elevation, and an
/// unmanifested exe can be heuristically treated as an installer candidate)
/// and opts into long paths and UTF-8 so the hook sees the same bytes on
/// Windows that it sees elsewhere.
///
/// Resource compilation needs `rc.exe` (Windows SDK, present wherever the MSVC
/// linker is) or `llvm-rc` on a cross-build host. A missing compiler degrades
/// to a cargo warning rather than a failed build, so `cargo install` on an
/// unusual host still produces a working guard — just one without metadata.
fn embed_windows_resources() {
    println!("cargo:rerun-if-env-changed=RC_PATH");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    let mut resource = winresource::WindowsResource::new();
    resource
        .set("ProductName", "Destructive Command Guard (dcg)")
        .set(
            "FileDescription",
            "dcg — PreToolUse hook that blocks destructive shell commands for AI coding agents",
        )
        .set("CompanyName", "Jeffrey Emanuel")
        .set("LegalCopyright", "Copyright (c) Jeffrey Emanuel. See LICENSE.")
        .set("OriginalFilename", "dcg.exe")
        .set("InternalName", "dcg")
        .set("Comments", "https://github.com/Dicklesworthstone/destructive_command_guard")
        .set("FileVersion", &version)
        .set("ProductVersion", &version)
        .set_manifest(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="Dicklesworthstone.dcg" version="1.0.0.0"/>
  <description>dcg - Destructive Command Guard</description>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>
      <activeCodePage xmlns="http://schemas.microsoft.com/SMI/2019/WindowsSettings">UTF-8</activeCodePage>
    </windowsSettings>
  </application>
</assembly>"#,
        );

    if let Err(e) = resource.compile() {
        println!(
            "cargo:warning=Windows VERSIONINFO/manifest resource not embedded (#303): {e}. \
             The binary still works; install rc.exe (Windows SDK) or llvm-rc, or set RC_PATH."
        );
    }
}
