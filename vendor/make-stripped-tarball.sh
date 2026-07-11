#!/usr/bin/env bash
#
# Reproducibly regenerate db-6.2.23-stripped.tar.gz from the upstream
# Berkeley DB 6.2.23 source distribution.
#
# This provides a third-party verifiable chain from Oracle's published
# tarball to the stripped tarball vendored in this repository: the upstream
# download is verified against UPSTREAM_SHA256, and the regenerated output
# is verified against STRIPPED_SHA256 (the same hash pinned in build.rs).
#
# Usage:
#   ./make-stripped-tarball.sh [path-to-upstream-db-6.2.23.tar.gz]
#
# If no path is given, the upstream tarball is downloaded from Oracle.

set -euo pipefail

BDB_VERSION="6.2.23"
UPSTREAM_URL="https://download.oracle.com/berkeley-db/db-${BDB_VERSION}.tar.gz"
UPSTREAM_SHA256="47612c8991aa9ac2f6be721267c8d3cdccf5ac83105df8e50809daea24e95dc7"
STRIPPED_SHA256="1a68ef6361f045adc66c9b69d4b28faa50f0ead0e2f6e64a95322610f094ef1b"

# All mtimes are clamped to a fixed timestamp so that the archive is
# byte-for-byte reproducible no matter when the recipe is run.
MTIME_CLAMP="2016-03-28T00:00:00Z"

vendor_dir="$(cd "$(dirname "$0")" && pwd)"
out_file="${vendor_dir}/db-${BDB_VERSION}-stripped.tar.gz"

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

check_sha256() {
  local file="$1" expected="$2" label="$3" actual
  actual="$(sha256 "$file")"
  if [ "$actual" != "$expected" ]; then
    echo "error: ${label} checksum mismatch" >&2
    echo "  expected: ${expected}" >&2
    echo "  computed: ${actual}" >&2
    exit 1
  fi
  echo "${label} checksum OK: ${actual}"
}

if ! tar --version 2>/dev/null | grep -q 'GNU tar'; then
  echo "error: GNU tar is required (for --sort=name)" >&2
  exit 1
fi

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

upstream="${1:-}"
if [ -z "$upstream" ]; then
  upstream="${workdir}/db-${BDB_VERSION}.tar.gz"
  echo "Downloading ${UPSTREAM_URL} ..."
  curl -fsSL -o "$upstream" "$UPSTREAM_URL"
fi
check_sha256 "$upstream" "$UPSTREAM_SHA256" "upstream tarball"

tar -xzf "$upstream" -C "$workdir"
(
  cd "${workdir}/db-${BDB_VERSION}"
  rm -rf docs lang examples build_android build_vxworks build_wince build_windows
  # dist/configure unconditionally generates include.tcl from this template,
  # so it must survive the stripping of the test suite.
  find test -type f ! -name include.tcl -delete
  find test -depth -type d -empty -delete
)
tar -C "$workdir" \
  --sort=name --mtime="$MTIME_CLAMP" --owner=0 --group=0 --numeric-owner \
  -cf - "db-${BDB_VERSION}" | gzip -n > "${workdir}/stripped.tar.gz"

check_sha256 "${workdir}/stripped.tar.gz" "$STRIPPED_SHA256" "stripped tarball"
mv "${workdir}/stripped.tar.gz" "$out_file"
echo "Wrote ${out_file}"
