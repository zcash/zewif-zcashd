# Vendored Berkeley DB

`db-6.2.23-stripped.tar.gz` is a size-reduced repackaging of the upstream
Berkeley DB 6.2.23 source distribution. It exists because the full upstream
tarball (~42 MB) exceeds the crates.io 10 MB package size limit; the stripped
tarball retains everything required by `build.rs` to configure and build the
`db_dump` utility on Unix platforms: `LICENSE`, `README`, `dist/`, `src/`,
`util/`, `build_unix/`, and `test/tcl/include.tcl` (required because
`dist/configure` unconditionally generates `include.tcl` from it).

## Provenance and verification

Upstream source: `db-6.2.23.tar.gz` as distributed by Oracle
(<https://download.oracle.com/berkeley-db/db-6.2.23.tar.gz>), SHA-256:

```
47612c8991aa9ac2f6be721267c8d3cdccf5ac83105df8e50809daea24e95dc7
```

Stripped tarball SHA-256 (also pinned in `build.rs` as `BDB_SHA256` and
verified there before extraction):

```
1a68ef6361f045adc66c9b69d4b28faa50f0ead0e2f6e64a95322610f094ef1b
```

The stripped tarball is byte-for-byte reproducible from the upstream
distribution by running [`make-stripped-tarball.sh`](make-stripped-tarball.sh)
(requires GNU tar), which downloads the upstream tarball, verifies its
checksum, strips it deterministically, and verifies the result against the
pinned hash. Third parties who do not wish to trust the vendored artifact can
run the script themselves to confirm the chain from Oracle's published
sources.
