use std::{env, fs, path::Path, process::Command};

const BDB_TARBALL: &str = "vendor/db-6.2.32.tar.gz";
const BDB_DIR_NAME: &str = "db-6.2.32";
const BDB_SHA256: &str = "a9c5e2b004a5777aa03510cfe5cd766a4a3b777713406b02809c17c8e0e7a8fb";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", BDB_TARBALL);

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    match target_os.as_str() {
        "linux" | "macos" | "freebsd" | "openbsd" | "netbsd" => {
            if let Err(e) = build_berkeley_db() {
                println!("cargo:warning=Failed to build vendored Berkeley DB: {}", e);
                println!(
                    "cargo:warning=The crate will fall back to using system-installed db_dump"
                );
            }
        }
        "windows" => {
            println!("cargo:warning=Berkeley DB vendoring is not supported on Windows");
            println!(
                "cargo:warning=Please ensure db_dump.exe is available in your PATH"
            );
        }
        other => {
            println!(
                "cargo:warning=Berkeley DB vendoring is not supported on platform: {}",
                other
            );
            println!("cargo:warning=Please ensure db_dump is available in your PATH");
        }
    }
}

fn build_berkeley_db() -> Result<(), String> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")
        .map_err(|e| format!("Failed to get CARGO_MANIFEST_DIR: {}", e))?;
    let out_dir =
        env::var("OUT_DIR").map_err(|e| format!("Failed to get OUT_DIR: {}", e))?;

    let tarball_path = Path::new(&manifest_dir).join(BDB_TARBALL);
    let out_path = Path::new(&out_dir);
    let bdb_src = out_path.join(BDB_DIR_NAME);
    let build_dir = bdb_src.join("build_unix");
    let db_dump_binary = out_path.join("db_dump");

    // Skip if already built
    if db_dump_binary.exists() {
        println!(
            "cargo:rustc-env=DB_DUMP_PATH={}",
            db_dump_binary.display()
        );
        return Ok(());
    }

    // Verify tarball checksum
    verify_checksum(&tarball_path)?;

    // Extract tarball into OUT_DIR if not already extracted
    if !bdb_src.exists() {
        let output = Command::new("tar")
            .args(["-xzf", tarball_path.to_str().unwrap()])
            .current_dir(out_path)
            .output()
            .map_err(|e| format!("Failed to execute tar: {}", e))?;

        if !output.status.success() {
            return Err(format!(
                "Failed to extract Berkeley DB: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
    }

    // Configure (BDB 6.2.32 has pointer-type mismatches that newer GCC treats as errors)
    let configure_output = Command::new("../dist/configure")
        .args([
            "--disable-shared",
            "--enable-static",
            "--disable-heap",
            "--disable-verify",
            "--disable-statistics",
            "--disable-replication",
            "--disable-cryptography",
            "--disable-partition",
        ])
        .env(
            "CFLAGS",
            "-Wno-error=incompatible-pointer-types -Wno-error=int-conversion",
        )
        .current_dir(&build_dir)
        .output()
        .map_err(|e| format!("Failed to execute configure: {}", e))?;

    if !configure_output.status.success() {
        return Err(format!(
            "Failed to configure Berkeley DB: {}",
            String::from_utf8_lossy(&configure_output.stderr)
        ));
    }

    // Build only db_dump
    let make_output = Command::new("make")
        .arg("db_dump")
        .current_dir(&build_dir)
        .output()
        .map_err(|e| format!("Failed to execute make: {}", e))?;

    if !make_output.status.success() {
        return Err(format!(
            "Failed to build db_dump: {}",
            String::from_utf8_lossy(&make_output.stderr)
        ));
    }

    // Copy the built binary to OUT_DIR root for a stable path
    let built_binary = build_dir.join("db_dump");
    if !built_binary.exists() {
        return Err(format!(
            "db_dump binary was not created at expected path: {}",
            built_binary.display()
        ));
    }
    fs::copy(&built_binary, &db_dump_binary)
        .map_err(|e| format!("Failed to copy db_dump to OUT_DIR: {}", e))?;

    println!(
        "cargo:rustc-env=DB_DUMP_PATH={}",
        db_dump_binary.display()
    );

    Ok(())
}

fn verify_checksum(tarball_path: &Path) -> Result<(), String> {
    let output = Command::new("sha256sum")
        .arg(tarball_path)
        .output()
        .or_else(|_| {
            // macOS uses shasum instead of sha256sum
            Command::new("shasum")
                .args(["-a", "256"])
                .arg(tarball_path)
                .output()
        })
        .map_err(|e| format!("Failed to compute checksum: {}", e))?;

    if !output.status.success() {
        return Err("Failed to compute tarball checksum".to_string());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let computed = stdout
        .split_whitespace()
        .next()
        .ok_or("Empty checksum output")?;

    if computed != BDB_SHA256 {
        return Err(format!(
            "Tarball checksum mismatch!\n  expected: {}\n  computed: {}",
            BDB_SHA256, computed
        ));
    }

    Ok(())
}
