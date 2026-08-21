#!/usr/bin/env bash
#
# RIPE-Netze abrufen und als IP-Hosts in Sophos Firewall/XGS synchronisieren.

set -uo pipefail

DEPENDENCIES=(curl awk sed shasum xmllint)
SCRIPT_NAME=$(basename "$0")
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
VERSION="1.0.0"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

if [[ -n "${NO_COLOR:-}" ]] || [[ "${TERM:-}" == "dumb" ]]; then
    RED=""
    GREEN=""
    YELLOW=""
    BLUE=""
    NC=""
fi

# --- Konfiguration: hier direkt anpassen -----------------------------------

# RIPE-Filter
RIPE_ORG=ORG-DTAG1-RIPE
RIPE_NETNAME_REGEX='^DTAG-DIAL'

# Sophos Web-Admin-Basis-URL (ohne /webconsole/APIController)
SOPHOS_URL=https://firewall.example.invalid:4444
SOPHOS_USERNAME=ripe-api

# Bevorzugt nicht hier eintragen. Stattdessen vor dem Aufruf exportieren:
# export SOPHOS_PASSWORD='...'
SOPHOS_PASSWORD=${SOPHOS_PASSWORD:-}

# Leer lassen, damit die Firewall ihre aktive API-Version verwendet.
SOPHOS_API_VERSION=

# Zertifikatsprüfung ist standardmäßig aktiv. Für eine interne CA:
SOPHOS_CA_CERT=
# Nur für einen kontrollierten Test mit selbstsigniertem Zertifikat:
SOPHOS_INSECURE=false

# Diese Gruppen werden ausschließlich durch das Skript verwaltet.
SOPHOS_GROUP_IPV4=${RIPE_ORG}-IPv4
SOPHOS_GROUP_IPV6=${RIPE_ORG}-IPv6

# Host-Objektname ist "<netname>-IPv4"/"<netname>-IPv6". Nur bei Bedarf (z.B.
# falls netname pro IP-Version doch nicht eindeutig ist) einen Hash-Suffix
# zur Kollisionsvermeidung erzwingen:
SOPHOS_NAME_HASH_SUFFIX=true

# Präfix, an dem das Skript seine eigenen, verwalteten Hosts auf der Firewall
# erkennt (Diff/Prune). Muss zum Anfang der erzeugten Namen passen, also zum
# gefilterten netname-Präfix aus RIPE_NETNAME_REGEX.
OBJECT_PREFIX=DTAG-DIAL
BATCH_SIZE=50

# Können für Testläufe per Umgebungsvariable überschrieben werden.
WORK_DIR=${WORK_DIR:-"$SCRIPT_DIR/work"}
OUTPUT_DIR=${OUTPUT_DIR:-"$SCRIPT_DIR/outputs"}

# --- Ende Konfiguration -----------------------------------------------------

CLEANUP_FILES=()

function usage() {
    cat <<EOM

RIPE-Netze abrufen und als IP-Hosts in Sophos Firewall/XGS synchronisieren.

usage: ${SCRIPT_NAME} [options]

options:
    --apply                     Änderungen an die Sophos Firewall senden.
    --prune                     Mit --apply: nicht mehr erwartete, verwaltete Hosts löschen.
    --raw-file      <datei>     Vorhandene RIPE-Rohantwort statt eines Downloads verwenden.
    -v|--verbose                Ausführlichere Ausgabe.
    --version                   Versionsinformation anzeigen.
    -h|--help                   Diese Hilfe anzeigen.

dependencies: ${DEPENDENCIES[@]}

Ohne --apply werden nur RIPE-Daten, Manifest und eine XML-Vorschau erzeugt.
Konfigurationswerte (RIPE_ORG, SOPHOS_URL, SOPHOS_USERNAME, ...) werden direkt
am Kopf dieses Skripts im Abschnitt "Konfiguration: hier direkt anpassen"
gesetzt.

examples:
    ${SCRIPT_NAME}
    ${SCRIPT_NAME} --raw-file ./work/ripe-raw.txt
    SOPHOS_PASSWORD='...' ${SCRIPT_NAME} --apply
    SOPHOS_PASSWORD='...' ${SCRIPT_NAME} --apply --prune

EOM
    exit 1
}

function main() {
    local raw_file=""
    local apply=false
    local prune=false
    local verbose=false

    while [ "$#" -gt 0 ]; do
        case "$1" in
        --apply)
            apply=true
            ;;
        --prune)
            prune=true
            ;;
        --raw-file)
            [ "$#" -ge 2 ] || { print_error "--raw-file benötigt einen Pfad"; usage; }
            shift
            raw_file="$1"
            ;;
        -v | --verbose)
            verbose=true
            ;;
        --version)
            echo "${SCRIPT_NAME} version ${VERSION}"
            exit 0
            ;;
        -h | --help)
            usage
            ;;
        *)
            print_error "Unbekannte Option: $1"
            usage
            ;;
        esac
        shift
    done

    if [ "$prune" = true ] && [ "$apply" != true ]; then
        print_error "--prune kann nur zusammen mit --apply verwendet werden"
        exit 1
    fi

    exit_on_missing_tools "${DEPENDENCIES[@]}"
    validate_batch_size "$BATCH_SIZE"

    trap cleanup_temp_files EXIT HUP INT TERM

    if [ "$verbose" = true ]; then
        print_info "Konfiguration: RIPE_ORG=$RIPE_ORG, RIPE_NETNAME_REGEX=$RIPE_NETNAME_REGEX, OBJECT_PREFIX=$OBJECT_PREFIX"
    fi

    local manifest_path
    manifest_path=$(run_ripe_pipeline "$raw_file") || exit 1

    if [ "$apply" != true ]; then
        print_info "Dry-Run beendet. Mit --apply werden die Änderungen an Sophos gesendet."
        return 0
    fi

    sync_to_sophos "$manifest_path" "$prune"
}

function run_ripe_pipeline() {
    local raw_file="$1"
    local raw_output filtered objects manifest preview filtered_data
    local manifest_count ipv4_count ipv6_count

    mkdir -p "$WORK_DIR" "$OUTPUT_DIR" || {
        print_error "Kann Arbeitsverzeichnisse nicht anlegen: $WORK_DIR, $OUTPUT_DIR"
        exit 1
    }

    raw_output="$WORK_DIR/ripe-raw.txt"
    filtered="$OUTPUT_DIR/${RIPE_ORG}_DTAG-DIAL_networks.txt"
    objects="$OUTPUT_DIR/${RIPE_ORG}_DTAG-DIAL_objects.txt"
    manifest="$OUTPUT_DIR/sophos-manifest.tsv"
    preview="$OUTPUT_DIR/sophos-import-preview.xml"

    fetch_ripe_raw "$raw_file" "$raw_output"

    filtered_data=$(make_temp) || exit 1
    run_ripe_filter "$raw_output" "$objects" "$filtered_data"
    write_networks_file "$filtered_data" "$filtered"
    build_manifest "$filtered_data" "$manifest"

    manifest_count=$(($(wc -l <"$manifest") - 1))
    ipv4_count=$(awk -F '\t' 'NR > 1 && $2 == "IPv4" { n++ } END { print n + 0 }' "$manifest")
    ipv6_count=$(awk -F '\t' 'NR > 1 && $2 == "IPv6" { n++ } END { print n + 0 }' "$manifest")
    if [ "$manifest_count" -le 0 ]; then
        print_error "Der Filter hat keine RIPE-Netzobjekte geliefert"
        exit 1
    fi

    write_xml_preview "$manifest" "$preview"

    print_success "Erzeugt: $manifest_count Hosts ($ipv4_count IPv4, $ipv6_count IPv6)"
    print_info "Manifest: $manifest"
    print_info "XML-Vorschau: $preview"

    printf '%s\n' "$manifest"
}

function fetch_ripe_raw() {
    local raw_file="$1"
    local raw_output="$2"

    if [ -n "$raw_file" ]; then
        [ -r "$raw_file" ] || {
            print_error "RIPE-Rohdatei nicht lesbar: $raw_file"
            exit 1
        }
        cp "$raw_file" "$raw_output" || {
            print_error "Konnte $raw_file nicht nach $raw_output kopieren"
            exit 1
        }
        print_info "Verwende RIPE-Rohdaten aus $raw_file"
        return 0
    fi

    print_info "Rufe RIPE-Objekte für $RIPE_ORG ab ..."
    curl --fail --silent --show-error --get \
        'https://rest.db.ripe.net/search.txt' \
        --data-urlencode 'source=ripe' \
        --data-urlencode 'inverse-attribute=org' \
        --data-urlencode 'type-filter=inetnum' \
        --data-urlencode 'type-filter=inet6num' \
        --data-urlencode 'flags=no-referenced' \
        --data-urlencode "query-string=$RIPE_ORG" \
        --output "$raw_output" || {
        print_error "RIPE-Abfrage fehlgeschlagen"
        exit 1
    }
}

function run_ripe_filter() {
    local raw_output="$1" objects_file="$2" filtered_data="$3"
    local awk_file

    awk_file=$(make_temp) || exit 1
    write_filter_awk "$awk_file"

    : >"$objects_file" || {
        print_error "Kann $objects_file nicht anlegen"
        exit 1
    }

    local deduped keyed
    deduped=$(make_temp) || exit 1
    keyed=$(make_temp) || exit 1

    awk -v wanted="$RIPE_NETNAME_REGEX" -v objects_file="$objects_file" \
        -f "$awk_file" "$raw_output" | LC_ALL=C sort -u >"$deduped" || {
        print_error "RIPE-Filterung fehlgeschlagen"
        exit 1
    }

    add_sort_key "$deduped" "$keyed"

    # Reihenfolge: erst alle inetnum (IPv4), dann inet6num (IPv6, "r" auf
    # Feld 2 kehrt die alphabetische Reihenfolge um), je Familie nach dem
    # normalisierten netname (Sortierschlüssel in Feld 1, siehe
    # normalize_netname()), damit z.B. "-002" vor "-010" vor "-100" steht.
    LC_ALL=C sort -t "$(printf '\t')" -k2,2r -k1,1 -k3,3 "$keyed" | cut -f2- >"$filtered_data" || {
        print_error "Sortierung der RIPE-Netze fehlgeschlagen"
        exit 1
    }
}

function add_sort_key() {
    local input="$1" output="$2"
    local type resource netname country status key

    : >"$output" || {
        print_error "Kann Sortierschlüssel-Datei nicht anlegen"
        exit 1
    }

    while IFS="$(printf '\t')" read -r type resource netname country status; do
        key=$(normalize_netname "$netname" "$OBJECT_PREFIX")
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$key" "$type" "$resource" "$netname" "$country" "$status" >>"$output"
    done <"$input"
}

function write_filter_awk() {
    local awk_file="$1"
    cat >"$awk_file" <<'AWK'
BEGIN { RS = ""; FS = "\n"; OFS = "\t" }
{
  type = resource = netname = country = status = ""
  for (i = 1; i <= NF; i++) {
    line = $i
    if (line ~ /^inetnum:[[:space:]]*/) {
      type = "inetnum"; sub(/^inetnum:[[:space:]]*/, "", line); resource = line
    } else if (line ~ /^inet6num:[[:space:]]*/) {
      type = "inet6num"; sub(/^inet6num:[[:space:]]*/, "", line); resource = line
    } else if (line ~ /^netname:[[:space:]]*/) {
      sub(/^netname:[[:space:]]*/, "", line); netname = line
    } else if (line ~ /^country:[[:space:]]*/) {
      sub(/^country:[[:space:]]*/, "", line); country = line
    } else if (line ~ /^status:[[:space:]]*/) {
      sub(/^status:[[:space:]]*/, "", line); status = line
    }
  }
  if ((type == "inetnum" || type == "inet6num") && netname ~ wanted) {
    gsub(/[[:space:]]+$/, "", resource)
    print type, resource, netname, (country == "" ? "-" : country), (status == "" ? "-" : status)
    print $0 > objects_file
    print "" > objects_file
  }
}
AWK
}

function write_networks_file() {
    local filtered_data="$1" filtered_output="$2"
    {
        printf 'type | network_or_range | netname | country | status\n'
        awk -F '\t' '{ print $1 " | " $2 " | " $3 " | " $4 " | " $5 }' "$filtered_data"
    } >"$filtered_output" || {
        print_error "Kann $filtered_output nicht schreiben"
        exit 1
    }
}

function build_manifest() {
    local filtered_data="$1" manifest_path="$2"
    local type resource netname country status
    local digest start end address prefix mask name netname_norm

    printf 'name\tfamily\thost_type\tvalue1\tvalue2\tnetname\tcountry\tstatus\n' \
        >"$manifest_path" || {
        print_error "Kann $manifest_path nicht anlegen"
        exit 1
    }

    while IFS="$(printf '\t')" read -r type resource netname country status; do
        digest=$(printf '%s' "$type|$resource" | shasum -a 256 | awk '{print substr($1, 1, 16)}')
        [ -n "$digest" ] || {
            print_error "Konnte Hash für $resource nicht berechnen"
            exit 1
        }
        netname_norm=$(normalize_netname "$netname" "$OBJECT_PREFIX")

        if [ "$type" = inetnum ]; then
            start=$(printf '%s' "$resource" | awk -F '[[:space:]]+-[[:space:]]+' '{print $1}')
            end=$(printf '%s' "$resource" | awk -F '[[:space:]]+-[[:space:]]+' '{print $2}')
            [ -n "$start" ] && [ -n "$end" ] || {
                print_error "Ungültiger IPv4-Bereich: $resource"
                exit 1
            }
            name="${netname_norm}-IPv4"
            [ "$SOPHOS_NAME_HASH_SUFFIX" != true ] || name="${name}-${digest}"
            printf '%s\tIPv4\tIPRange\t%s\t%s\t%s\t%s\t%s\n' \
                "$name" "$start" "$end" "$netname" "$country" "$status" \
                >>"$manifest_path"
        else
            address=${resource%/*}
            prefix=${resource#*/}
            case "$prefix" in
            '' | *[!0-9]*)
                print_error "Ungültiges IPv6-Präfix: $resource"
                exit 1
                ;;
            esac
            [ "$prefix" -le 128 ] || {
                print_error "Ungültiges IPv6-Präfix: $resource"
                exit 1
            }
            mask=$(ipv6_mask "$prefix")
            name="${netname_norm}-IPv6"
            [ "$SOPHOS_NAME_HASH_SUFFIX" != true ] || name="${name}-${digest}"
            printf '%s\tIPv6\tNetwork\t%s\t%s\t%s\t%s\t%s\n' \
                "$name" "$address" "$mask" "$netname" "$country" "$status" \
                >>"$manifest_path"
        fi
    done <"$filtered_data"
}

function write_xml_preview() {
    local manifest_path="$1" preview_path="$2"
    local name family host_type value1 value2 netname country status

    {
        printf '<!-- Vorschau ohne Zugangsdaten; für die Anwendung wird in Batches gesendet. -->\n'
        printf '<Set operation="add">\n'
        tail -n +2 "$manifest_path" | while IFS="$(printf '\t')" read -r name family host_type value1 value2 netname country status; do
            emit_host_xml "$name" "$family" "$host_type" "$value1" "$value2" "$netname" "$country" "$status"
        done
        printf '</Set>\n'
    } >"$preview_path" || {
        print_error "Kann $preview_path nicht schreiben"
        exit 1
    }
}

function sync_to_sophos() {
    local manifest_path="$1" prune="$2"
    local existing expected

    validate_sophos_credentials

    ensure_sophos_group IPv4 "$SOPHOS_GROUP_IPV4"
    ensure_sophos_group IPv6 "$SOPHOS_GROUP_IPV6"

    existing=$(make_temp) || exit 1
    get_sophos_entities IPHost "$OBJECT_PREFIX" "$existing"
    LC_ALL=C sort -u "$existing" -o "$existing"

    expected=$(create_missing_hosts "$manifest_path" "$existing") || exit 1

    update_sophos_group_members IPv4 "$SOPHOS_GROUP_IPV4" "$manifest_path"
    update_sophos_group_members IPv6 "$SOPHOS_GROUP_IPV6" "$manifest_path"

    if [ "$prune" = true ]; then
        prune_stale_hosts "$existing" "$expected"
    fi

    print_success "Synchronisierung erfolgreich abgeschlossen."
}

function validate_sophos_credentials() {
    [ -n "${SOPHOS_URL:-}" ] || {
        print_error "SOPHOS_URL fehlt"
        exit 1
    }
    [ "$SOPHOS_URL" != "https://firewall.example.invalid:4444" ] || {
        print_error "SOPHOS_URL im Skriptkopf noch nicht angepasst"
        exit 1
    }
    [ -n "${SOPHOS_USERNAME:-}" ] || {
        print_error "SOPHOS_USERNAME fehlt"
        exit 1
    }
    if [ -z "${SOPHOS_PASSWORD:-}" ]; then
        printf 'Sophos-Passwort für %s: ' "$SOPHOS_USERNAME" >&2
        read -r -s SOPHOS_PASSWORD
        printf '\n' >&2
    fi
    [ -n "$SOPHOS_PASSWORD" ] || {
        print_error "SOPHOS_PASSWORD ist leer"
        exit 1
    }

    SOPHOS_URL=${SOPHOS_URL%/}
    case "$SOPHOS_URL" in
    https://*) ;;
    *)
        print_error "SOPHOS_URL muss mit https:// beginnen"
        exit 1
        ;;
    esac
    API_ENDPOINT="$SOPHOS_URL/webconsole/APIController"
}

function ensure_sophos_group() {
    local family="$1" group="$2"
    local names action response

    names=$(make_temp) || exit 1
    action=$(make_temp) || exit 1
    response=$(make_temp) || exit 1

    get_sophos_entities IPHostGroup "$group" "$names"
    if grep -Fqx "$group" "$names"; then
        return 0
    fi

    print_info "Lege Hostgruppe $group an ..."
    printf '<Set operation="add"><IPHostGroup><Name>%s</Name><IPFamily>%s</IPFamily><Description>Automatisch aus RIPE verwaltet</Description></IPHostGroup></Set>\n' \
        "$(xml_escape "$group")" "$family" >"$action"
    sophos_api_call "$action" "$response"
    check_sophos_response "$response" "Gruppe $group anlegen"
}

function create_missing_hosts() {
    local manifest_path="$1" existing_file="$2"
    local expected missing_manifest missing_count

    expected=$(make_temp) || exit 1
    missing_manifest=$(make_temp) || exit 1

    awk -F '\t' 'NR > 1 { print $1 }' "$manifest_path" | LC_ALL=C sort -u >"$expected"

    awk -F '\t' 'NR == FNR { seen[$1] = 1; next } FNR > 1 && !seen[$1] { print }' \
        "$existing_file" "$manifest_path" >"$missing_manifest"
    missing_count=$(wc -l <"$missing_manifest" | tr -d ' ')
    print_info "$missing_count neue Hosts werden angelegt; vorhandene verwaltete Hosts werden beibehalten."

    if [ "$missing_count" -gt 0 ]; then
        send_host_batches "$missing_manifest"
    fi

    printf '%s\n' "$expected"
}

function send_host_batches() {
    local missing_manifest="$1"
    local batch response count
    local name family host_type value1 value2 netname country status

    batch=$(make_temp) || exit 1
    response=$(make_temp) || exit 1
    count=0
    : >"$batch"

    while IFS="$(printf '\t')" read -r name family host_type value1 value2 netname country status; do
        if [ "$count" -eq 0 ]; then printf '<Set operation="add">\n' >"$batch"; fi
        emit_host_xml "$name" "$family" "$host_type" "$value1" "$value2" "$netname" "$country" "$status" >>"$batch"
        count=$((count + 1))
        if [ "$count" -ge "$BATCH_SIZE" ]; then
            printf '</Set>\n' >>"$batch"
            sophos_api_call "$batch" "$response"
            check_sophos_response "$response" "Host-Batch"
            count=0
        fi
    done <"$missing_manifest"

    if [ "$count" -gt 0 ]; then
        printf '</Set>\n' >>"$batch"
        sophos_api_call "$batch" "$response"
        check_sophos_response "$response" "Host-Batch"
    fi
}

function update_sophos_group_members() {
    local family="$1" group="$2" manifest_path="$3"
    local action response host

    action=$(make_temp) || exit 1
    response=$(make_temp) || exit 1

    {
        printf '<Set operation="update"><IPHostGroup><Name>%s</Name><IPFamily>%s</IPFamily><Description>Automatisch aus RIPE verwaltet</Description><HostList>' \
            "$(xml_escape "$group")" "$family"
        awk -F '\t' -v family="$family" 'NR > 1 && $2 == family { print $1 }' "$manifest_path" |
            while IFS= read -r host; do
                printf '<Host>%s</Host>' "$(xml_escape "$host")"
            done
        printf '</HostList></IPHostGroup></Set>\n'
    } >"$action"

    sophos_api_call "$action" "$response"
    check_sophos_response "$response" "Mitglieder von Gruppe $group aktualisieren"
}

function prune_stale_hosts() {
    local existing_file="$1" expected_file="$2"
    local stale action response stale_count host

    stale=$(make_temp) || exit 1
    comm -23 "$existing_file" "$expected_file" |
        awk -v prefix="$OBJECT_PREFIX" 'index($0, prefix) == 1' >"$stale"
    stale_count=$(wc -l <"$stale" | tr -d ' ')
    if [ "$stale_count" -eq 0 ]; then
        return 0
    fi

    print_info "Lösche $stale_count veraltete verwaltete Hosts ..."
    action=$(make_temp) || exit 1
    response=$(make_temp) || exit 1
    printf '<Remove>\n' >"$action"
    while IFS= read -r host; do
        printf '<IPHost><Name>%s</Name></IPHost>\n' "$(xml_escape "$host")" >>"$action"
    done <"$stale"
    printf '</Remove>\n' >>"$action"

    sophos_api_call "$action" "$response"
    check_sophos_response "$response" "veraltete Hosts löschen"
}

function get_sophos_entities() {
    local entity="$1" pattern="$2" result_file="$3"
    local action response

    action=$(make_temp) || exit 1
    response=$(make_temp) || exit 1

    printf '<Get><%s><Filter><key name="Name" criteria="like">%s</key></Filter></%s></Get>\n' \
        "$entity" "$(xml_escape "$pattern")" "$entity" >"$action"
    sophos_api_call "$action" "$response"
    xmllint --format "$response" 2>/dev/null |
        sed -n 's/.*<Name>\([^<]*\)<\/Name>.*/\1/p' >"$result_file"
}

function sophos_api_call() {
    local action_file="$1" response_file="$2"
    local request_file request_tag
    local curl_args=()

    request_file=$(make_temp) || exit 1
    if [ -n "$SOPHOS_API_VERSION" ]; then
        request_tag="<Request APIVersion=\"$(xml_escape "$SOPHOS_API_VERSION")\">"
    else
        request_tag='<Request>'
    fi

    {
        printf '%s<Login><Username>%s</Username><Password>%s</Password></Login>' \
            "$request_tag" "$(xml_escape "$SOPHOS_USERNAME")" "$(xml_escape "$SOPHOS_PASSWORD")"
        cat "$action_file"
        printf '</Request>\n'
    } >"$request_file"
    chmod 600 "$request_file"

    curl_args=(--fail --silent --show-error --request POST "$API_ENDPOINT" -F "reqxml=<$request_file" --output "$response_file")
    [ "$SOPHOS_INSECURE" != true ] || curl_args+=(--insecure)
    [ -z "$SOPHOS_CA_CERT" ] || curl_args+=(--cacert "$SOPHOS_CA_CERT")

    curl "${curl_args[@]}" || {
        print_error "Sophos-API-Aufruf fehlgeschlagen"
        exit 1
    }
    grep -qi 'authentication successful' "$response_file" || {
        print_error "Sophos-Authentifizierung fehlgeschlagen; Antwort: $response_file"
        exit 1
    }
}

function check_sophos_response() {
    local response_file="$1" context="$2"
    local formatted codes bad

    formatted=$(make_temp) || exit 1
    xmllint --format "$response_file" >"$formatted" 2>/dev/null || {
        print_error "Ungültige XML-Antwort bei $context: $response_file"
        exit 1
    }

    codes=$(sed -n 's/.*<Status code="\([0-9][0-9]*\)".*/\1/p' "$formatted")
    [ -n "$codes" ] || {
        print_error "Keine Statuscodes bei $context: $response_file"
        exit 1
    }

    bad=$(printf '%s\n' "$codes" | awk '$1 != 200 && $1 != 201 && $1 != 202 && $1 != 203 && $1 != 216 { print }')
    [ -z "$bad" ] || {
        print_error "Sophos meldet Fehlercode(s) $bad bei $context; Antwort: $response_file"
        exit 1
    }
}

function emit_host_xml() {
    local name="$1" family="$2" host_type="$3" value1="$4" value2="$5"
    local netname="$6" country="$7" status="$8"
    local group

    if [ "$family" = IPv4 ]; then group=$SOPHOS_GROUP_IPV4; else group=$SOPHOS_GROUP_IPV6; fi

    printf '<IPHost><Name>%s</Name><IPFamily>%s</IPFamily><Description>%s</Description><HostType>%s</HostType>' \
        "$(xml_escape "$name")" "$family" \
        "$(xml_escape "RIPE $netname; country=$country; status=$status")" "$host_type"
    if [ "$host_type" = IPRange ]; then
        printf '<StartIPAddress>%s</StartIPAddress><EndIPAddress>%s</EndIPAddress>' "$value1" "$value2"
    else
        printf '<IPAddress>%s</IPAddress><Subnet>%s</Subnet>' "$value1" "$value2"
    fi
    printf '<HostGroupList><HostGroup>%s</HostGroup></HostGroupList></IPHost>\n' "$(xml_escape "$group")"
}

function normalize_netname() {
    local netname="$1" prefix="$2"
    local num padded

    # Vereinheitlicht die numerische Endung von Namen der Form "<prefix>N"
    # bzw. "<prefix>-N": mit Bindestrich und auf 3 Stellen mit führenden
    # Nullen aufgefüllt (RIPE liefert das uneinheitlich: z.B. "DTAG-DIAL22"
    # ohne Bindestrich bei IPv4, "DTAG-DIAL-102" mit Bindestrich bei IPv6).
    # Bewusst strikt an "prefix" gebunden (statt an ein generisches
    # "endet auf Ziffern"-Muster), damit Namen wie "DTAG-DIAL-TEMP-MIG" oder
    # ein zufälliges "...-V6" nicht fälschlich als Nummer erkannt werden.
    if [[ "$netname" =~ ^${prefix}-?([0-9]{1,3})$ ]]; then
        num="${BASH_REMATCH[1]}"
        printf -v padded '%03d' "$num"
        printf '%s-%s' "$prefix" "$padded"
    else
        printf '%s' "$netname"
    fi
}

function xml_escape() {
    printf '%s' "$1" | sed \
        -e 's/&/\&amp;/g' \
        -e 's/</\&lt;/g' \
        -e 's/>/\&gt;/g' \
        -e 's/"/\&quot;/g' \
        -e "s/'/\&apos;/g"
}

function ipv6_mask() {
    local prefix="$1"
    local full rest result index part

    full=$((prefix / 16))
    rest=$((prefix % 16))
    result=
    index=0
    while [ "$index" -lt 8 ]; do
        if [ "$index" -lt "$full" ]; then
            part=ffff
        elif [ "$index" -eq "$full" ] && [ "$rest" -gt 0 ]; then
            case "$rest" in
            1) part=8000 ;; 2) part=c000 ;; 3) part=e000 ;; 4) part=f000 ;;
            5) part=f800 ;; 6) part=fc00 ;; 7) part=fe00 ;; 8) part=ff00 ;;
            9) part=ff80 ;; 10) part=ffc0 ;; 11) part=ffe0 ;; 12) part=fff0 ;;
            13) part=fff8 ;; 14) part=fffc ;; 15) part=fffe ;;
            esac
        else
            part=0
        fi
        if [ -z "$result" ]; then result=$part; else result="$result:$part"; fi
        index=$((index + 1))
    done
    printf '%s' "$result"
}

function validate_batch_size() {
    local value="$1"
    case "$value" in
    '' | *[!0-9]*)
        print_error "BATCH_SIZE muss eine positive Ganzzahl sein"
        exit 1
        ;;
    esac
    [ "$value" -gt 0 ] || {
        print_error "BATCH_SIZE muss größer als 0 sein"
        exit 1
    }
}

function make_temp() {
    local file
    file=$(mktemp "${TMPDIR:-/tmp}/ripe-sophos.XXXXXX") || {
        print_error "mktemp fehlgeschlagen"
        exit 1
    }
    CLEANUP_FILES+=("$file")
    printf '%s\n' "$file"
}

function cleanup_temp_files() {
    if [ "${#CLEANUP_FILES[@]}" -gt 0 ]; then
        rm -f "${CLEANUP_FILES[@]}"
    fi
}

function exit_on_missing_tools() {
    for cmd in "$@"; do
        if command -v "$cmd" &>/dev/null; then
            continue
        fi
        print_error "Benötigtes Werkzeug '$cmd' ist nicht installiert oder nicht im PATH"
        exit 1
    done
}

function print_info() {
    echo -e "${BLUE}$1${NC}" >&2
}

function print_success() {
    echo -e "${GREEN}✅ $1${NC}" >&2
}

function print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}" >&2
}

function print_error() {
    echo -e "${RED}❌ Fehler: $1${NC}" >&2
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
    exit 0
fi
