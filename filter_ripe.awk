BEGIN {
  RS = ""
  FS = "\n"
  list_file = "outputs/ORG-DTAG1-RIPE_DTAG-DIAL_networks.txt"
  object_file = "outputs/ORG-DTAG1-RIPE_DTAG-DIAL_objects.txt"
  print "object_type | network | netname | country | status" > list_file
  print "# RIPE objects: org ORG-DTAG1-RIPE; netname starts with DTAG-DIAL\n" > object_file
}

{
  netname = ""
  network = ""
  object_type = ""
  country = ""
  status = ""

  for (i = 1; i <= NF; i++) {
    if ($i ~ /^netname:[[:space:]]*/) {
      netname = $i
      sub(/^netname:[[:space:]]*/, "", netname)
    } else if ($i ~ /^inetnum:[[:space:]]*/) {
      object_type = "inetnum"
      network = $i
      sub(/^inetnum:[[:space:]]*/, "", network)
    } else if ($i ~ /^inet6num:[[:space:]]*/) {
      object_type = "inet6num"
      network = $i
      sub(/^inet6num:[[:space:]]*/, "", network)
    } else if ($i ~ /^country:[[:space:]]*/) {
      country = $i
      sub(/^country:[[:space:]]*/, "", country)
    } else if ($i ~ /^status:[[:space:]]*/) {
      status = $i
      sub(/^status:[[:space:]]*/, "", status)
    }
  }

  if (netname ~ /^DTAG-DIAL/) {
    print object_type " | " network " | " netname " | " country " | " status >> list_file
    print $0 "\n" >> object_file
  }
}
