#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/ripe-sophos-test.XXXXXX")
trap 'rm -rf "$TEST_ROOT"' EXIT HUP INT TERM

WORK_DIR="$TEST_ROOT/work" OUTPUT_DIR="$TEST_ROOT/outputs" \
  "$PROJECT_DIR/RIPE-IPtoSophosXGS.sh" \
  --raw-file "$SCRIPT_DIR/fixtures/ripe-sample.txt"

MANIFEST="$TEST_ROOT/outputs/sophos-manifest.tsv"
PREVIEW="$TEST_ROOT/outputs/sophos-import-preview.xml"

[ "$(wc -l < "$MANIFEST" | tr -d ' ')" -eq 3 ]
grep -qE $'^DTAG-DIAL-DE-IPv4(-[0-9a-f]{16})?\tIPv4\tIPRange\t80.128.0.0\t80.128.0.255\tDTAG-DIAL-DE\t' "$MANIFEST"
grep -qE $'^DTAG-DIAL-V6-IPv6(-[0-9a-f]{16})?\tIPv6\tNetwork\t2003:db8:1234::\tffff:ffff:ffff:0:0:0:0:0\tDTAG-DIAL-V6\t' "$MANIFEST"
! grep -q 'OTHER-NET' "$MANIFEST"
grep -q '<HostGroup>ORG-DTAG1-RIPE-IPv4</HostGroup>' "$PREVIEW"
grep -q '<HostGroup>ORG-DTAG1-RIPE-IPv6</HostGroup>' "$PREVIEW"

printf 'Offline-Test erfolgreich.\n'
