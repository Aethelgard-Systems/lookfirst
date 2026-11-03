# Release-Belegblatt – ausfüllen vor Freigabe (#668 P7)

Vorlage, kein ausgefüllter Releasebericht und keine Freigabe.
Alle offenen Felder bleiben UNKNOWN. Keine Token, Kundendaten, Logrohtexte oder
vollständigen Session-IDs eintragen; ausschließlich Links auf bereinigte Belege.
IMPLEMENTED ≠ TESTED ≠ DEPLOYED ≠ RUNTIME_VERIFIED.

## Identität

| Feld | Wert | Evidenzklasse / Beleg |
|---|---|---|
| Vollständige Commit-SHA | UNKNOWN | UNKNOWN |
| Paketversion und Artefakt-SHA256 | UNKNOWN | UNKNOWN |
| Abhängigkeiten/Lock oder genaue getestete Versionen | UNKNOWN | UNKNOWN |
| Geprüfter Head / unabhängiger Reviewer | UNKNOWN | UNKNOWN |
| Review-Head exakt gleich Release-SHA | UNKNOWN | UNKNOWN |
| Lizenz-Gate: Apache-2.0 / LICENSE / NOTICE / Rechteprüfung | UNKNOWN | UNKNOWN |
| Namensprüfung / dokumentierte Freigabe | UNKNOWN | UNKNOWN |
| Freigabe MARCO (Chat-/Ticketbezug) | UNKNOWN | UNKNOWN |
| Datum / zuständiger Owner | UNKNOWN | UNKNOWN |

## Getestete Konfiguration

| Feld | Wert | Evidenzklasse / Beleg |
|---|---|---|
| Clientname + Version | UNKNOWN | UNKNOWN |
| Betriebssystem + Python/MCP-Version | UNKNOWN | UNKNOWN |
| Transport (stdio / Streamable HTTP) | UNKNOWN | UNKNOWN |
| HTTP TLS/Bearer/Proxy-Grenze, keine Werte | UNKNOWN | UNKNOWN |
| Freigabekanal (Elicitation / Seite / Webhook) | UNKNOWN | UNKNOWN |
| Regeln/Schleuse/Hook – Referenz/Hash ohne private Inhalte | UNKNOWN | UNKNOWN |
| Upstreams / Werkzeugklasse / Test-Datenart | UNKNOWN | UNKNOWN |

Eine eigene Zeile pro tatsächlich geprüftem Client-/Transport-Paar:

| Client/Version | Transport | Kanal | Zeitpunkt | Ergebnis | Beleg |
|---|---|---|---|---|---|
| UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN |

## Abnahmebelege

| Prüfung | Ergebnis | Evidenzklasse / Link |
|---|---|---|
| Konfigurationscheck / Werkzeugnamen | UNKNOWN | UNKNOWN |
| Lesen / Ablehnung / Timeout ohne Ausführung | UNKNOWN | UNKNOWN |
| Angezeigter Inhalt und bindende Freigabe | UNKNOWN | UNKNOWN |
| Ausführung genau einmal / unklarer Ausgang / Sperrverhalten | UNKNOWN | UNKNOWN |
| Rücklesen ok / fehlgeschlagen / unklar | UNKNOWN | UNKNOWN |
| Audit-Kette inkl. Manipulation und abgeschnittenem Ende | UNKNOWN | UNKNOWN |
| Maskierung / unbekannte Platzhalter / Antworttypen | UNKNOWN | UNKNOWN |
| Getrennte Sitzungen / neue Verbindung / kein Token | UNKNOWN | UNKNOWN |
| Wiederanlauf / Rückweg / Gesundheitsprüfung | UNKNOWN | UNKNOWN |
| Echte Pilotabnahme durch MARCO | UNKNOWN | UNKNOWN |
| Pilotzeitraum mindestens eine Woche | UNKNOWN | UNKNOWN |
| Mindestens20 echte Vorgänge im Pilot | UNKNOWN | UNKNOWN |
| Fehlversuche und Überraschungen, bereinigte Beleglinks | UNKNOWN | UNKNOWN |

Ein lokaler HTTP-Test ist TESTED, kein produktiver Pilotbeleg. Kein Häkchen aus
ungeprüften PR-Beschreibungen übernehmen: INTERNAL_REPORTED bleibt so markiert.

## Grenzen und Entscheidung

- Offene Befunde mit Schweregrad/Ticket: UNKNOWN.
- Selbstfreigabe durch autonome Elicitation-Clients: UNKNOWN für diese Konfiguration.
- Sitzungsbindung ist keine Personenidentität; Token plus Session-ID teilt Sitzung.
- Lokaler Code/gleicher OS-Nutzer kann Regeln/Schlüssel umgehen; keine Sandboxzusage.
- Geschützter Transport außerhalb des vertrauenswürdigen Hosts: UNKNOWN.
- Externe Toolargumente, anonymisierte Daten, Kostenobergrenzen: UNKNOWN.
- Tatsächlicher Rückweg, Daten-/Schlüsselbewahrung und Verantwortlicher: UNKNOWN.

| Status | Wert | Beleg |
|---|---|---|
| IMPLEMENTED | UNKNOWN | UNKNOWN |
| TESTED | UNKNOWN | UNKNOWN |
| DEPLOYED | UNKNOWN | UNKNOWN |
| RUNTIME_VERIFIED | UNKNOWN | UNKNOWN |

Nächster Schritt / Owner: UNKNOWN. MARCO-Entscheidung: UNKNOWN.
Wenn eine Entscheidung fehlt, entsprechendes Ticket mit bestehendem Marco-Block
führen; dieses Blatt erzeugt keine Authority und keinen Deployauftrag.
