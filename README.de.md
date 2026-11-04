# 🛡️ lookfirst (bisher „Torwächter“)

**Eine Schutzschicht zwischen KI-Agenten und ihren Werkzeugen.** Jede *schreibende* Aktion (Geld überweisen, Datensatz löschen,
Mail senden, Ticket schließen) läuft durch: **Vorschau → ein Mensch bestätigt → Ausführung → Rücklesen → manipulationserkennendes
Prüfprotokoll.** Lesende Aktionen laufen unverändert durch.

lookfirst ist ein [MCP](https://modelcontextprotocol.io)-Proxy: zwischen beliebigem MCP-Client (Claude, ChatGPT, Cursor, eigener
Agent) und beliebigen MCP-Servern. Auf beiden Seiten ändert sich nichts.

```
KI-Client ──MCP──▶ lookfirst ──MCP──▶ Upstream-Server (Bank, CRM, Mail, Dateien, …)
                      │
                      ├─ Regeldatei YAML: allow | confirm | deny je Werkzeug (Standard aus Tool-Annotationen)
                      ├─ Bestätigung: im Client (MCP-Elicitation) · lokale Freigabeseite · Webhook
                      ├─ Rücklesen: nach dem Schreiben erneut lesen → ok | unklar | fehlgeschlagen
                      └─ Protokoll: JSONL, Hash-Kette, Ed25519-signiert → `lookfirst verify-log`
```

*English version: [README.md](README.md). Architektur: [docs/architecture.md](docs/architecture.md).*

## Stand
0.2.0, Stand 31. Oktober 2026. Vorbereitung Launch-Vorstellung Anfang November 2026. Läuft offline Ende-zu-Ende (Demo unten); vorbereitet für den lokalen Piloten (#609/#610, #807, #846). **KEIN PRODUKTIONSRELEASE:** echter Produktiveinsatz unterliegt gezielten Tests und Freigabe durch MARCO (die frühere Mindestwartephase von ≥ 1 Woche / ≥ 20 Vorgängen ist seit MARCO 31.10. „Kurzer Lieferweg“ keine Pflichtschwelle mehr; Messung des Reifegrads weiterhin über `lookfirst pilot-status`). **Lizenz:** Apache-2.0 (Entscheidung MARCO 27.10.2026; siehe `LICENSE`). Die Lizenz räumt Nutzungsrechte am Code ein; sie bedeutet weder, dass der Build freigegeben, noch dass der Produktname geklärt ist.

Messung des Gate-Reifegrads jederzeit über: `lookfirst pilot-status --config lookfirst.yaml`.

## Schnellstart (60 Sekunden, offline)

```bash
pip install -e .            # oder: uvx --from . lookfirst demo
lookfirst demo
```

Die Demo startet eine Fake-Bank als MCP-Server, stellt lookfirst davor und spielt einen Agenten: Kontostand läuft durch,
eine Überweisung stoppt für dein `y/N`, das Ergebnis wird rückgelesen, dann wird eine Protokollzeile verändert und
`verify-log` erkennt es. Drehbuch fürs Bildschirmvideo: [demo/VIDEO.md](demo/VIDEO.md).

## Mit echtem Client

Windows: reines Python, `py -m pip install <pfad-oder-git-url>` sollte funktionieren, ist von uns aber **noch nicht auf Windows getestet**.

1. `lookfirst.yaml` schreiben (Vorlage: [lookfirst/demo_files/lookfirst.yaml](lookfirst/demo_files/lookfirst.yaml)): Upstreams, Regeln, Bestätigungskanäle, Pfade.
2. `lookfirst keygen --config lookfirst.yaml` – einmalig den Ed25519-Schlüssel (0600) erzeugen.
3. `lookfirst serve --config lookfirst.yaml` (stdio) oder `--transport http --port 8470` (Streamable HTTP unter `/mcp`).
4. Den Client auf lookfirst statt auf den Upstream zeigen lassen.
5. Jederzeit: `lookfirst verify-log --config lookfirst.yaml`.

## Wie ein Aufruf entschieden wird

| Lage | Standard | Grund |
|---|---|---|
| Werkzeug meldet `readOnlyHint: true` | **allow** | Lesen ist harmlos |
| Werkzeug meldet `destructiveHint: true` | **confirm** | ein Mensch entscheidet |
| `destructiveHint: false` (Schreiben, aber umkehrbar) | **confirm** | trotzdem Schreiben |
| keine Annotationen | **confirm** | unbekannt = fragen |
| ausdrückliche Regel `rules.tools.<name>.action` | diese | Regel schlägt Annotation; `deny` führt nie aus |

Bestätigungskanäle in dieser Reihenfolge: **(1)** MCP-Elicitation im Client, wenn er es kann und die Argumente vollständig
passen (Argument-JSON ≤ 800 Zeichen – längere Vorschauen werden nie abgeschnitten, sondern gehen an Freigabeseite oder Webhook;
ohne beide wird abgelehnt); **(2)** lokale Freigabeseite
(`confirm.web`); **(3)** Webhook (`confirm.webhook`), der die Vorschau bekommt und über `POST /decision/<id>` mit einem
**Token je Aufruf** antwortet (HMAC der Aufruf-ID – ein mitgelesenes Token öffnet nichts anderes; Webhook-URLs nur `https://`)
und den `args_sha256` aus der Vorschau mitschickt – fehlt er oder passt er nicht → 403, eine Entscheidung gilt also nur für genau
die gezeigten Argumente; die Freigabeseite bindet ihre Knöpfe genauso. **Ein Webhook-Empfänger muss dem Menschen `tool_display`, `summary` und `arguments_display` zeigen – nie das rohe `tool` oder `arguments`:** die Anzeigefelder sind maskiert (unsichtbare, Bidi- und leerzeichenähnliche Zeichen erscheinen als `\uXXXX`), die Rohfelder nicht, ein Empfänger, der sie zeigt, lässt sich täuschen –
hier hängt sich später AETHELGARDs „Braucht dich“ ein. Alle Kanäle teilen einen Timeout; **Timeout = Ablehnung**.

Grenzen: **(a)** Elicitation beantwortet der *Client*. Ein autonomer Client, der Elicitation selbst beantwortet, gibt sich selbst
frei – für solche Clients `confirm.elicitation: false` setzen, dann entscheidet nur Freigabeseite oder Webhook. **(b)** Die
Freigabeseite akzeptiert nur Anfragen, deren `Host` dieser Server ist und die nicht cross-site kommen (`Origin`/`Sec-Fetch-Site`),
plus CSRF-Token je Prozess; sie hat keinen Login und ist nur für 127.0.0.1 gedacht. **(c)** Bei `--transport http` weiß das Gate
nicht, *wer* aufruft. Ohne `http.token_file` startet es nur auf Loopback (mit Warnung: jeder lokale Prozess kann Werkzeuge rufen);
mit Token braucht jede Anfrage `Authorization: Bearer <token>`, sonst 401. Außerhalb von Loopback ist das Token Pflicht. Das
Bearer-Token ist Anmeldung, **keine Transportverschlüsselung**: außerhalb des lokalen vertrauenswürdigen Hosts TLS oder einen
anderen geschützten Transport (Reverse-Proxy mit TLS, SSH-Tunnel, VPN) vorschalten. Wovor
das Gate **nicht** schützt (andere Wege zum selben System, Zugriff desselben Nutzers auf Schlüssel und Regeln):
[docs/threat-model.md](docs/threat-model.md).

Rücklesen (`rules.tools.<name>.readback`): nach einer bestätigten Schreibaktion ruft lookfirst ein *Lese*-Werkzeug auf und
vergleicht erwartete Felder (`$args.x`, `$result.y`). Ergebnis `ok`, `unklar` (nicht prüfbar) oder `fehlgeschlagen` (Abweichung),
zurückgegeben in `structuredContent.lookfirst` – nie „erledigt“ ohne Beleg.


## Bekannte Grenzen (unabhängige Gegenprüfung, 03.11.2026)

Das sind dokumentierte Grenzen, keine versteckten Fehler. Die Nummern stammen aus der Gegenprüfung und weichen von den B-Nummern in `docs/threat-model.md` ab. Zu jeder gibt es einen Test, der das heutige Verhalten festhält oder das gewünschte als erwarteten Fehlschlag markiert.

| Nr. | Grenze | Was tun |
|---|---|---|
| B4.1 | Wird das Prüfprotokoll am Ende gekürzt **und** die `.head`-Datei gelöscht, sieht die übrige Hash-Kette weiter intakt aus. `lookfirst verify-log` endet dann mit Exit 0 und einer Warnung (`head sidecar missing`). | Die Warnung in eigenen Prüfungen wie einen Fehler behandeln. Eine Kopie der `.head`-Datei (oder nur die letzte Folgenummer) regelmäßig nachziehen; `verify-log` kann noch nicht gegen eine externe Kopie prüfen, der Abgleich ist Handarbeit. **Außerhalb der Schreibrechte dessen aufbewahren, der das Protokoll kürzen kann** – eine `.head` neben dem Protokoll lässt sich zusammen mit ihm löschen. |
| B5.1 | Der Datenschutzfilter (`schleuse`) ist ein deterministischer Mustervergleich. Eine IBAN mit Zeilenumbruch, Text mit unsichtbaren Zeichen oder ein nur Base64-kodiertes Geheimnis im Fließtext wird **nicht** erkannt. Er verringert Abfluss, er anonymisiert nicht. | Sich bei Geheimnissen nicht darauf verlassen; Geheimnisse gar nicht in Werkzeugargumente schreiben. Heute ebenfalls nicht erkannt: Schlüssel wie `db_password` oder `access_token` (B5.2, als erwarteter Fehlschlag festgehalten). |
| B7.1 | Mit `confirm.elicitation: true` warnt `lookfirst serve` beim Start nicht vor autonomen Clients, die die Elicitation selbst beantworten könnten (Selbstfreigabe). | Für autonome Clients `confirm.elicitation: false` setzen, dann entscheiden nur die Webseite oder der Webhook – **und** den Agenten netzwerkseitig von dieser Seite trennen (anderer Rechner, Container oder Netzwerk-Namespace, oder Firewall-Regel pro Benutzer). Ein eigener OS-Benutzer genügt nicht: jeder lokale Benutzer erreicht Loopback. `identity_header` nur nutzen, wenn das Backend ausschließlich für den Auth-Proxy erreichbar ist; der Header wird ungeprüft übernommen, ein Agent mit direktem Zugriff setzt ihn selbst und gibt sich frei. |

## Datenschutz-Schleuse (Vorschau v0.3)

Private Angaben verlassen das Haus nur als Platzhalter (`schleuse:` in der Konfiguration):
Werkzeug-Antworten an den KI-Client werden maskiert (IBAN mit Prüfziffer, Kartennummern, E-Mail, Telefon, Zugangsdaten mit bekannter Form – Schlüssel von GitHub/OpenAI/Anthropic/AWS u. a., JWT, private Schlüssel; bei `password=…`, `api_key: …`, `Authorization: Bearer …` und `nutzer:kennwort@`-Adressen nur der Wert; in strukturierten Antworten auch Werte unter Schlüsseln wie `password`/`token`/`api_key`. Nicht erkannt: freie Geheimnisse ohne bekannte Form oder Schlüsselnamen –, eigene Namensliste,
eigene Muster), auch in Vorschau, Ablehnungstexten und Protokoll. Nutzt der Client einen Platzhalter, löst der lookfirst
ihn lokal auf – nur selbst ausgegebene; unbekannte werden abgelehnt. Grenze: reduziert den Abfluss, anonymisiert nicht
vollständig (Beträge, Daten, Händler bleiben deutbar). Argumente an externe Werkzeuge werden noch nicht maskiert.
Werkzeug-Metadaten (alles außer dem Namen) werden ebenfalls maskiert. Sitzungstrennung bei mehreren HTTP-Clients ist
über echtes Streamable HTTP auf Loopback mit zwei Clients getestet (`tests/test_mehrclient_http.py`): Client B wird A's
Platzhalter verweigert, nichts erreicht den Upstream, A's Freigabe-Dialog geht nie an B, eine neue Verbindung beginnt leer.
Gebunden wird an die MCP-Sitzung (`Mcp-Session-Id`), nicht an die Person: wer HTTP-Token *und* Sitzungs-ID hat, teilt die
Sitzung. Im Pilotbetrieb noch nicht belegt.

## Prüfprotokoll

Append-only JSONL. Jeder Eintrag enthält den Hash des Vorgängers und eine Ed25519-Signatur; `ts` sind ganzzahlige Millisekunden.
Eine `.head`-Datei hält letzten Hash und Seq, **signiert** mit demselben Schlüssel. `verify-log` meldet veränderte, entfernte,
umsortierte, eingefügte oder gefälschte Einträge mit Zeilennummer sowie Abschneiden am Ende, solange die `.head`-Datei da ist –
eine gelöschte `.head`-Datei ergibt eine Warnung, nie ein sauberes Urteil.
Argumente stehen nur als SHA-256 im Protokoll; die lesbare Zusammenfassung schon (Geheimnisse gehören nicht in Summaries – siehe Schwärzung).

## Schwärzung (eigener Code, optional)

`redact.hook: "paket.modul:funktion"` bekommt die Vorschau, bevor sie gezeigt oder verschickt wird, und gibt eine geschwärzte Kopie
zurück. Standard: unverändert. Die eingebauten Platzhalter für IBAN, Karten, E-Mail, Telefon, Zugangsdaten und die Namensliste
liefert die Schleuse (siehe „Datenschutz-Schleuse“ oben); der Hook ist nur für eigene Zusatzregeln obendrauf. Er bekommt eine
Kopie und darf alles Angezeigte maskieren, nie aber die Bindung: Aufruf-ID und `args_sha256` kommen immer aus Gate und Registry,
auch auf der Freigabeseite und in `/open` (#668 P3).

## Compliance

`docs/compliance-mapping.md` ordnet zu, was das Gate *technisch* zu EU AI Act Art. 12/14, DORA und MaRisk beiträgt –
Anforderung → Funktion → Beleg im Protokoll → Lücke. Keine Rechtsberatung, keine Zertifizierung; erlaubte Formulierung ist
„unterstützt technisch bei …“.

## Abgrenzung zu agent-postbox

[agent-postbox](https://github.com/Aethelgard-Systems/agent-postbox) sichert **Übergaben zwischen Agenten** (wer hat was an wen
übergeben, gegengezeichnet). lookfirst sichert **Aktionen an Werkzeugen** (was ein Agent an der Welt tun darf, von einem
Menschen bestätigt). Gleiche Familie „Trust-Tools“, gleiche Beleg-Denke, andere Naht. Beides passt zusammen: eine Übergabe kommt
über agent-postbox, die daraus folgende Aktion läuft trotzdem durch das Tor.

## Update, Rückweg, Fehler

**Vor jedem Start oder nach jeder Änderung prüfen:** `lookfirst check --config lookfirst.yaml [--timeout 10]` lädt die
Konfiguration, prüft Regeln, Prüfschlüssel, `http.token_file` (wird nie ausgegeben), Freigabekanäle, Schleuse und
Schwärzungs-Hook und verbindet sich einmal mit jedem Upstream, um dessen Werkzeuge abzurufen. Eine Zeile je Prüfpunkt (Ausgabe
englisch wie alle Meldungen): `OK` = in Ordnung, `WARN` = läuft, aber anschauen, `ERROR` = **Fehler**, läuft so nicht.
Exit 0 ohne ERROR, 2 mit ERROR. Startet das Gate nicht und ruft kein Werkzeug auf.

**Update.** Konfiguration, Prüfprotokoll (`*.jsonl` + `.head`) und Schlüssel (`*.key` + `.pub`) liegen neben der Konfiguration,
nicht im Paket – Update und Rückweg fassen sie nicht an. Diese vier Dateien vorher wegsichern.

```bash
pip show lookfirst                                   # aktuelle Version / Commit notieren
pipx install --force <pfad-oder-git-url>   # oder: pip install -U <pfad>
lookfirst check --config lookfirst.yaml
lookfirst verify-log --config lookfirst.yaml
```

Danach den Client neu starten (stdio: der Client startet das Gate) bzw. den `serve --transport http`-Prozess.

**Rückweg.** Vorige Version genauso installieren, auf den notierten Commit festgelegt:
`pipx install --force "git+<git-url>@<voriger-commit>"`, danach wieder `check` und `verify-log`.
Nie einen neuen Schlüssel erzeugen, um ein Problem zu „lösen“: alte Einträge sind nur mit der alten `.pub` prüfbar.

**Was ein Werkzeug-Ergebnis bedeutet** (`structuredContent.lookfirst`):

| Ergebnis | Was passiert ist | Was tun |
|---|---|---|
| `denied` (Regel, `not approved`, Timeout, kein Kanal) | **nichts** ausgeführt | rechtzeitig freigeben oder Regel ändern; Wiederholen ist gefahrlos |
| `executed`, `readback: ok` | erledigt und nachgeprüft | nichts |
| `executed`, `readback: none` | ausgeführt, keine Rücklese-Regel | bei Bedarf im Zielsystem nachsehen; `readback`-Regel ergänzen |
| `executed`, `readback: unklar` / „outcome unclear“ | **vielleicht passiert**, nicht prüfbar | *vor* jeder Wiederholung im Zielsystem nachsehen – blind wiederholen kann doppelt ausführen |
| `executed`, `readback: fehlgeschlagen` | passiert, aber das Zielsystem zeigt etwas anderes | im Zielsystem prüfen, von Hand korrigieren; nicht wiederholen |
| `Denied: schleuse: unknown or expired placeholder …` | nichts ausgeführt | Agent die Daten in dieser Sitzung neu holen lassen |

**Fehler beim Start und bei `check`:**

| Meldung | Bedeutung | Was tun |
|---|---|---|
| `audit key missing … run lookfirst keygen` | noch kein Signaturschlüssel | einmalig `lookfirst keygen --config …` (nicht nach Verlust – dann Sicherung zurückspielen) |
| `… action must be one of ('allow', 'confirm', 'deny')` | Tippfehler in einer Regel | genannte Regel korrigieren |
| `rule '…' matches no tool` (WARN) | Regel wirkt nicht; ein `deny` fällt auf den Standard zurück | genauen Werkzeugnamen nutzen; bei mehreren Upstreams `<upstream>__<werkzeug>` |
| `upstream … not reachable` | Server nicht gestartet, falscher Befehl/URL oder keine Antwort im Zeitlimit | Server starten, `command`/`url` korrigieren, `--timeout` erhöhen |
| `http.token_file not readable` / `needs at least 32 characters` | Token-Datei fehlt oder zu kurz | zufälliges Token mit 32+ Zeichen in diese Datei schreiben |
| `HTTP on '…' needs http.token_file` | Adresse außerhalb Loopback ohne Token | `http.token_file` setzen oder an 127.0.0.1 binden |
| `no approval channel` (WARN) | jeder `confirm`-Aufruf wird abgelehnt | `confirm.web` oder `confirm.webhook` einschalten |
| `verify-log`: `TAMPERED` | Protokoll verändert, gekürzt oder gefälscht | Datei als Beleg behalten, mit Sicherung vergleichen; nicht löschen |

## Tests

`python -m unittest discover -s tests` – 95 Tests, synthetische Daten, MCP im Speicher plus ein echter stdio-Unterprozess: Regeln,
Parameterbindung (`args_sha256`), Freigabe ja/nein/Timeout, Web- und Webhook-Kanal, Rücklesen ok/unklar/fehlgeschlagen, Protokollintegrität
(Manipulationserkennung bei veränderten, entfernten, umsortierten, eingefügten Zeilen, gefälschter Signatur, Abschneiden oder fremdem Schlüssel),
Lesezugriffe unverändert durchgeleitet, mehrere Upstreams, HTTP-Bearer-Token, Schleuse (Maskierung, Platzhalter, Sitzungsbindung, Zugangsdaten),
`lookfirst check`, `lookfirst pilot-status` und Launch-Gate-Messung.
