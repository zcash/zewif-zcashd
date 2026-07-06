use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use zewif::Data;

/// Errors arising while dumping a `wallet.dat` BDB file to records via the
/// `db_dump` utility.
#[derive(Debug, thiserror::Error)]
pub enum BdbDumpError {
    /// The `db_dump` utility could not be executed.
    #[error("error executing {} against {}: {source}", db_dump_path.display(), filepath.display())]
    DbDumpExec {
        db_dump_path: PathBuf,
        filepath: PathBuf,
        source: std::io::Error,
    },

    /// The `db_dump` utility exited unsuccessfully.
    #[error("db_dump failed with status {status}: {stderr}")]
    DbDumpFailed {
        status: std::process::ExitStatus,
        stderr: String,
    },

    /// A data line in the `db_dump` output held invalid hexadecimal.
    #[error("invalid hex in db_dump output: {0}")]
    InvalidHex(#[source] zewif::Error),

    /// A key line had no corresponding value line.
    #[error("found a key without a corresponding value")]
    UnmatchedKey,

    /// The same key appeared more than once in the dump.
    #[error("non-uniqueness in keys detected")]
    NonUniqueKeys,
}

pub struct BDBDump {
    pub header_records: HashMap<String, String>,
    pub data_records: HashMap<Data, Data>,
}

impl BDBDump {
    /// Resolves the path to the db_dump utility, preferring the vendored version.
    fn resolve_db_dump_path() -> PathBuf {
        if let Some(vendored_path) = option_env!("DB_DUMP_PATH") {
            let path = PathBuf::from(vendored_path);
            if path.exists() {
                return path;
            }
        }

        PathBuf::from("db_dump")
    }

    /// Dumps the BDB database at `filepath`, automatically resolving the db_dump binary.
    ///
    /// Uses the vendored db_dump if available, falling back to a system-installed version.
    pub fn from_file(filepath: &Path) -> Result<Self, BdbDumpError> {
        let db_dump_path = Self::resolve_db_dump_path();
        Self::from_file_with_path(&db_dump_path, filepath)
    }

    /// Dumps the BDB database at `filepath` using the specified `db_dump_path` binary.
    pub fn from_file_with_path(db_dump_path: &Path, filepath: &Path) -> Result<Self, BdbDumpError> {
        // Execute the `db_dump` utility
        let output = Command::new(db_dump_path)
            .arg(filepath)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|source| BdbDumpError::DbDumpExec {
                db_dump_path: db_dump_path.to_path_buf(),
                filepath: filepath.to_path_buf(),
                source,
            })?;

        // Check if db_dump executed successfully
        if !output.status.success() {
            return Err(BdbDumpError::DbDumpFailed {
                status: output.status,
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }

        // Convert the stdout to a string for parsing
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Initialize HashMaps to hold header and data records
        let mut header_records: HashMap<String, String> = HashMap::new();
        let mut data_records: HashMap<Data, Data> = HashMap::new();

        // Flag to indicate if we're past the header
        let mut in_data_section = false;

        // Temporary variable to hold the key
        let mut current_key: Option<Data> = None;

        let mut records_count = 0;

        // Iterate over each line of the db_dump output
        for line in stdout.lines() {
            let trimmed = line.trim();

            // Check for the end of the header section
            if trimmed == "HEADER=END" {
                in_data_section = true;
                continue;
            }

            // Parse header lines
            if !in_data_section {
                if let Some(eq_pos) = trimmed.find('=') {
                    let key = &trimmed[..eq_pos];
                    let value = &trimmed[eq_pos + 1..];
                    header_records.insert(key.to_string(), value.to_string());
                } else {
                    eprintln!("Invalid header line: {}", trimmed);
                }
                continue;
            }

            if line.starts_with("DATA=END") {
                break;
            }

            // Each data entry line starts with a space; remove it
            let hex_str = trimmed.trim_start_matches(' ');

            // Decode the hexadecimal string
            let bytes = Data::from_hex(hex_str).map_err(BdbDumpError::InvalidHex)?;

            // Alternate between key and value
            if current_key.is_none() {
                current_key = Some(bytes);
            } else {
                let key = current_key.take().unwrap();
                let value = bytes;
                data_records.insert(key, value);
                records_count += 1;
            }
        }

        // Check if there was an unmatched key without a corresponding value
        if current_key.is_some() {
            return Err(BdbDumpError::UnmatchedKey);
        }

        if records_count != data_records.len() {
            return Err(BdbDumpError::NonUniqueKeys);
        }

        Ok(BDBDump { header_records, data_records })
    }
}
