# RIPE-Netze nach Sophos XGS synchronisieren

`RIPE-IPtoSophosXGS.sh` ruft die direkt mit `ORG-DTAG1-RIPE` verknüpften
`inetnum`- und `inet6num`-Objekte aus der RIPE Database ab, filtert auf
`netname: DTAG-DIAL…` und erzeugt daraus Sophos-IP-Hostobjekte.

- IPv4-Objekte werden verlustfrei als `IPRange` übernommen.
- IPv6-CIDRs werden als `Network` mit IPv6-Netzmaske übernommen.
- Sophos verlangt getrennte Hostgruppen für IPv4 und IPv6; diese heißen standardmäßig `<RIPE_ORG>-IPv4`/`-IPv6`.
- Objektnamen sind `<netname>-IPv4`/`<netname>-IPv6` und bleiben bei unverändertem netname stabil. Das setzt voraus, dass `netname` pro IP-Version eindeutig ist (bei `DTAG-DIAL*` durch den enthaltenen nummerischen Suffix der Fall). Optional per `SOPHOS_NAME_HASH_SUFFIX=true` einen Hash-Suffix erzwingen, falls das nicht zutrifft.
- Standardmäßig läuft das Skript ohne Änderungen an der Firewall (Dry-Run).

## Voraussetzungen

- Bash, `curl`, `awk`, `sed`, `shasum` und `xmllint`
- aktivierter Sophos-Firewall-API-Zugriff
- dedizierter API-Administrator mit passenden Rechten
- erlaubte Quell-IP und HTTPS-Zugriff auf den Web-Admin-Port

## Verwendung

Konfiguration steht direkt am Kopf von `RIPE-IPtoSophosXGS.sh` (Abschnitt
„Konfiguration: hier direkt anpassen“) – dort `RIPE_ORG`, `SOPHOS_URL`,
`SOPHOS_USERNAME` und die übrigen Werte vor dem ersten Lauf anpassen.

Zuerst nur RIPE abrufen und Ausgabe prüfen:

```bash
./RIPE-IPtoSophosXGS.sh
```

Das erzeugt unter `outputs/` die gefilterten Netze, das Sophos-Manifest und
eine XML-Vorschau ohne Zugangsdaten. Erst danach anwenden:

```bash
export SOPHOS_PASSWORD='das-api-passwort'
./RIPE-IPtoSophosXGS.sh --apply
```

Beim ersten Lauf legt das Skript die beiden verwalteten Gruppen an. Vorhandene
Objekte mit gleichem stabilen Namen werden nicht erneut angelegt. Die Gruppen
werden anschließend exakt auf den aktuellen RIPE-Bestand gesetzt.

Veraltete, vom Skript benannte Objekte werden nur auf ausdrücklichen Wunsch
gelöscht:

```bash
./RIPE-IPtoSophosXGS.sh --apply --prune
```

`--prune` sollte erst nach einem erfolgreichen Testlauf verwendet werden.
Referenzierte Objekte kann Sophos nicht löschen; in diesem Fall bricht das
Skript mit dem von Sophos zurückgegebenen Statuscode ab.

## Offline testen

Eine vorhandene RIPE-Textantwort kann ohne erneuten Abruf verarbeitet werden:

```bash
./RIPE-IPtoSophosXGS.sh --raw-file ./work/ripe-raw.txt
```

Der mitgelieferte Offline-Test spricht weder RIPE noch eine Firewall an:

```bash
./tests/offline-test.sh
```

## Sicherheit

Das Passwort wird nicht in den dauerhaften Ausgaben gespeichert. Ohne
`SOPHOS_PASSWORD` fragt das Skript es verdeckt ab. Die temporäre XML-Anfrage
erhält Dateimodus `600`. Die TLS-Zertifikatsprüfung bleibt aktiv; bevorzugt
`SOPHOS_CA_CERT` für eine interne CA konfigurieren. `SOPHOS_INSECURE=true`
sollte nur für kontrollierte Tests eingesetzt werden.

Die RIPE-Daten bilden Datenbankzuordnungen ab und nicht zwingend den aktuellen
globalen BGP-Zustand.
