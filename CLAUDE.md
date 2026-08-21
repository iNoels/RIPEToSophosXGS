# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project does

`RIPE-IPtoSophosXGS.sh` fetches all `inetnum`/`inet6num` objects directly linked to a
RIPE organisation (`org: ORG-DTAG1-RIPE` by default) via the RIPE REST API,
keeps only objects whose `netname` matches a prefix (`^DTAG-DIAL` by default),
and syncs the result into two Sophos XGS/Sophos Firewall IP host groups
(IPv4 and IPv6) via the Sophos XML Firewall API. It is a single self-contained
Bash script — there is no build step, package manager, or compiled artifact.

## Commands

Run the offline test suite (no network, no firewall — uses `tests/fixtures/ripe-sample.txt`):

```bash
./tests/offline-test.sh
```

There is no other test runner, linter, or build command in this repo. When
changing `RIPE-IPtoSophosXGS.sh`, extend `tests/offline-test.sh` and/or
`tests/fixtures/ripe-sample.txt` rather than adding a new test framework.

Dry run against real RIPE data (writes to `outputs/`, never touches the firewall):

```bash
./RIPE-IPtoSophosXGS.sh
```

Re-run fully offline against a previously saved RIPE response:

```bash
./RIPE-IPtoSophosXGS.sh --raw-file ./work/ripe-raw.txt
```

Apply to the firewall (only after reviewing the dry-run output):

```bash
export SOPHOS_PASSWORD='...'
./RIPE-IPtoSophosXGS.sh --apply
./RIPE-IPtoSophosXGS.sh --apply --prune   # also deletes stale managed hosts
```

Configuration (`RIPE_ORG`, `SOPHOS_URL`, `SOPHOS_USERNAME`,
`SOPHOS_GROUP_IPV4/6`, `SOPHOS_NAME_HASH_SUFFIX`, `OBJECT_PREFIX`,
`BATCH_SIZE`, ...) is set directly at
the top of `RIPE-IPtoSophosXGS.sh` (the "Konfiguration: hier direkt anpassen"
block) — there is no external config file. `SOPHOS_PASSWORD` is the one
exception: it must never be hardcoded, only exported as an environment
variable before running, or entered interactively when prompted.

## Architecture

The script follows the `main()`-function-with-guard-clause pattern (see
`.claude/skills/bash`): `usage()`, then `main()` (argument parsing, dependency
checks, orchestration), then business-logic functions, then utility functions
(`xml_escape`, `ipv6_mask`, `make_temp`, `print_*`), ending in the
`[[ "${BASH_SOURCE[0]}" == "${0}" ]]` guard. It never uses `set -e` — every
fallible command is checked explicitly and fails with a colored `print_error`
message. `WORK_DIR`/`OUTPUT_DIR` stay overridable via environment variables
(needed by `tests/offline-test.sh` to run in an isolated temp directory); all
other configuration is fixed at the top of the script.

Everything happens inside `RIPE-IPtoSophosXGS.sh`, in one linear pipeline:

1. **Fetch** — `curl` against `rest.db.ripe.net/search.txt` using an inverse
   search on `org` (`--raw-file` skips this and reuses a saved response).
   `flags=no-referenced` keeps referenced contact objects (persons, roles)
   out of the response, so the raw text contains only `inetnum`/`inet6num`
   objects. Raw output goes to `work/ripe-raw.txt`.
2. **Filter** — an AWK program is written inline (heredoc, `RS=""` so each
   RPSL object is one record) that extracts `netname`/`country`/`status` and
   keeps only records matching `RIPE_NETNAME_REGEX`. The default
   `^DTAG-DIAL` is deliberately a prefix match, not an exact one — it also
   catches names like `DTAG-DIAL2` or `DTAG-DIAL-123`. Produces
   `outputs/${RIPE_ORG}_DTAG-DIAL_networks.txt` (compact) and
   `..._objects.txt` (full RPSL).
   - **Note:** `filter_ripe.awk` at the repo root is a standalone legacy
     copy of this same logic (hardcoded output paths, no CLI). The script
     does not call it — it has its own inline copy. Keep both in sync if you
     change filtering rules, or consider retiring the standalone file.
   - After deduping, `add_sort_key()` prepends each record with its
     `normalize_netname()` result (see Manifest below) so the final sort
     orders by the *normalized* netname (`-002` before `-010` before
     `-100`), not the raw one — then the key column is stripped again. This
     must stay ahead of the sort; sorting on the raw `netname` first and
     normalizing afterwards (in `build_manifest`) puts records in
     lexicographic, not numeric, order. Order: all `inetnum` (IPv4) before
     `inet6num` (IPv6), then normalized netname within each family.
3. **Manifest** — before naming, `normalize_netname()` canonicalizes RIPE's
   inconsistent `DTAG-DIAL` numeric suffix: `DTAG-DIAL22` (no hyphen, seen on
   IPv4) and `DTAG-DIAL-102` (with hyphen, seen on IPv6 — and occasionally
   without on IPv6 too) all become `DTAG-DIAL-<NNN>` (hyphen, zero-padded to
   3 digits). It is strictly anchored to `OBJECT_PREFIX` (`^${OBJECT_PREFIX}-?[0-9]{1,3}$`)
   rather than a generic "ends in digits" pattern, so unrelated names (e.g. a
   `-V6` suffix or `DTAG-DIAL-TEMP-MIG`) are left untouched. The Sophos object
   name is then `<normalized-netname>-IPv4` / `-IPv6`. Because normalization
   can make two originally-different `netname` values collide (as it does for
   real DTAG data), naming relies on `SOPHOS_NAME_HASH_SUFFIX=true` (default)
   to append a `sha256(type|resource)`-based suffix per family
   (`<name>-IPv4-<hash>`) for guaranteed uniqueness; set it to `false` only if
   you've confirmed the normalized `netname` is unique per IP family.
   IPv4 stays a `IPRange` (start/end); IPv6 CIDR is converted to
   `IPAddress` + `Subnet` mask (computed locally in `ipv6_mask()`, no
   external library). Result: `outputs/sophos-manifest.tsv`.
4. **XML preview** — `outputs/sophos-import-preview.xml`, generated without
   credentials, always produced even without `--apply`.
5. **Apply (`--apply`)** — logs into the Sophos XML Firewall API at
   `https://<SOPHOS_URL>/webconsole/APIController`, ensures both host groups
   exist, diffs the manifest against existing `IPHost` objects with the
   configured prefix (via `Get`/`Filter`), adds only the missing hosts in
   batches of `BATCH_SIZE`, then resets each group's `HostList` to exactly
   the current manifest. Every response is validated with `xmllint` and
   checked for Sophos status codes (200/201/202/203/216 = success).
6. **Prune (`--prune`, requires `--apply`)** — deletes managed hosts (matched
   by `OBJECT_PREFIX`) that exist on the firewall but are no longer in the
   manifest. Only runs on explicit request.

Key invariants to preserve when editing:
- `OBJECT_PREFIX` must stay a literal prefix of every name the manifest
  produces (default `DTAG-DIAL`, matching `RIPE_NETNAME_REGEX`) — it is the
  `like`-filter used both to find this script's own managed `IPHost` objects
  on the firewall (`get_sophos_entities`) and to decide what `--prune` is
  allowed to delete. Changing `RIPE_NETNAME_REGEX`'s prefix without updating
  `OBJECT_PREFIX` to match breaks that identification.
- Object names must stay stable across reruns against unchanged RIPE data
  (no new/duplicate Sophos objects for the same network); see the naming
  note under Manifest above.
- The script never persists `SOPHOS_PASSWORD` to disk; TLS verification is on
  by default (`SOPHOS_INSECURE`/`SOPHOS_CA_CERT` are explicit opt-outs).
- Temporary files must be created via the `make_temp()` helper, which
  registers them in the `CLEANUP_FILES` array for removal by the
  `EXIT`/`HUP`/`INT`/`TERM` trap. Every `x=$(make_temp)` call must be followed
  by `|| exit 1` — it runs inside a command substitution subshell, so an
  internal `exit` there only ends the subshell, not the whole script, unless
  the caller explicitly checks the exit status.
- The script requires `curl`, `awk`, `sed`, `shasum`, and `xmllint` on `PATH`
  and fails fast if any are missing.

## Scope limitation

Only `inetnum`/`inet6num` objects directly linked to the org via `org:` are
fetched. `route`/`route6` and `aut-num` objects are **not** queried, so the
result is a RIPE-database organisation attribution, not necessarily a
complete list of prefixes the org currently announces via BGP.

## Sophos API prerequisites

- The Sophos Firewall API is **disabled by default** and must be turned on
  manually on the device before `--apply` can work (SFOS 22.0:
  `Administration > API access`).
- The web-admin HTTPS admin port (used in `SOPHOS_URL`) is commonly `4444`,
  but is configurable per device.
- Use a dedicated API administrator with least-privilege write access, and
  allow only the trusted automation host's source IP.
- `SOPHOS_API_VERSION` and the exact XML tags/menu path must match the
  target's installed SFOS version; leave it empty to let the firewall use
  its active API version.

## Known gaps

- The Sophos API side (`RIPE-IPtoSophosXGS.sh --apply`) has not been verified
  against a real XGS/Sophos Firewall.
