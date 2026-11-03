# Compliance-Mapping: Was agent-gate (Torwächter) technisch zu EU AI Act Art. 12/14, DORA und MaRisk beiträgt

> **Keine Rechtsberatung, keine Zertifizierung.** Dieses Dokument ordnet Funktionen von agent-gate (Arbeitsname „Torwächter“) den
> Anforderungen aus Rechtstexten zu, damit ein Betreiber oder Prüfer schnell sieht, *welchen Nachweis das Werkzeug liefern kann* und
> *was es nicht leistet*. Ob eine Pflicht im Einzelfall gilt (z. B. ob ein KI-System „hochriskant“ nach Anhang III ist, ob ein
> Unternehmen unter DORA oder die MaRisk fällt), entscheiden Jurist:innen und die zuständige Aufsicht – nicht dieses Dokument und nicht
> das Werkzeug. Erlaubte Formulierung gegenüber Kunden: **„unterstützt technisch bei …“**. Nicht erlaubt: „konform“, „zertifiziert“,
> „erfüllt Art. 14“.
>
> Stand 17.10.2026, Verfasser FABLE. Quellen: EU-Kommission AI-Act-Service-Desk (konsolidierte Fassung EUR-Lex 02024R1689-20260727 vom
> 27.07.2026, inkl. Änderungen durch den „Digital Omnibus on AI“, ABl. L 2026/1744), Springlex-Wiedergabe von DORA (ABl. L 333 vom
> 27.12.2022), BaFin/Bundesbank Rundschreiben 06/2026 (BA) MaRisk vom 30.06.2026. Evidenzklasse `EXTERNAL`, Abrufdatum 17.10.2026.
> Grundlage war die Recherche `torwaechter-recherche-2026-10_argon_v1.1` (ARGON); ihre Aussagen wurden hier gegen die Primärquellen
> nachgeprüft, Abweichungen stehen in Abschnitt 5.

## 1. Was agent-gate ist (in einem Absatz)

Ein MCP-Proxy zwischen KI-Agent und Werkzeug. Jeder schreibende Werkzeugaufruf wird **angehalten**, als Vorschau gezeigt, von einem
Menschen **freigegeben oder abgelehnt** (Elicitation im Client, lokale Freigabeseite oder Webhook), erst dann ausgeführt, danach
**zurückgelesen** (Ist-Zustand vs. Erwartung) und in ein **append-only, hash-verkettetes, Ed25519-signiertes Protokoll** geschrieben
(`torwaechter verify-log` erkennt veränderte, entfernte, umsortierte, eingefügte oder gefälschte Einträge, Abschneiden am Ende über die
signierte `.head`-Datei). Lesende Werkzeuge laufen durch; was nicht als lesend bekannt ist, wird gefragt. Details: `README.md`,
`docs/architecture.md`; Protokollformat identisch mit `evidence-v1` von agent-postbox.

Protokollfelder je Eintrag: `seq, ts (ms), event (allow|preview|decision|result|readback), call_id, tool, args_sha256, summary,
decision (allow|confirm|deny|approve), by (Regel/Kanal: rule:…, default:…, elicitation, web, webhook, timeout, policy), result_sha256,
readback (ok|unklar|fehlgeschlagen|none), note, prev, hash, sig`.

## 2. EU AI Act – Verordnung (EU) 2024/1689, konsolidiert 27.07.2026

**Geltung (Art. 113, geändert durch Digital Omnibus):** Anforderungen an Hochrisiko-KI-Systeme (Kapitel III Abschnitte 1–3, darunter
Art. 12 und 14) gelten ab **2. Dezember 2027** für Systeme nach Anhang III und ab **2. August 2028** für Systeme nach Anhang I
(`EXTERNAL`, AI-Act-Service-Desk Art. 113, 17.10.2026). Die Pflichten treffen **Anbieter** (Design) und **Betreiber** (Art. 26:
Aufsicht durch kompetente Personen, Aufbewahrung der Logs). Ob ein Agent mit Schreibzugriff überhaupt ein Hochrisiko-System ist,
hängt vom Einsatzzweck ab (Anhang III) – ein Entwicklerwerkzeug für interne Automatisierung ist es in der Regel nicht. Das Mapping
gilt also für Betreiber, die agent-gate *vor* ein als hochriskant eingestuftes System schalten, und als Blaupause für alle anderen.

| Anforderung | Artikel / Quelle + Datum | agent-gate-Funktion | Beleg im Protokoll | Lücke / Grenze |
|---|---|---|---|---|
| Automatische Aufzeichnung von Ereignissen über die Lebensdauer des Systems | Art. 12 Abs. 1 (Service-Desk, 17.10.2026) | Jeder Aufruf durch den Proxy erzeugt automatisch Einträge; kein Weg, einen Aufruf ohne Eintrag auszuführen (sofern der Agent nur über agent-gate auf das Werkzeug kommt) | `event=allow/preview` mit `ts`, `tool`, `args_sha256`, `call_id` | Aufrufe, die am Proxy vorbei direkt zum Werkzeug gehen, sieht agent-gate nicht; der Betreiber muss den Direktweg technisch schließen |
| Rückverfolgbarkeit: Situationen mit Risiko erkennen, Post-Market-Monitoring, Betriebsüberwachung durch den Betreiber | Art. 12 Abs. 2 lit. a–c, Art. 26 Abs. 5 | Vorschau + Entscheidung + Ergebnis + Rücklesen sind je `call_id` verkettet; Abweichungen zwischen Erwartung und Ist werden als `readback=fehlgeschlagen` markiert | Kette `preview → decision → result → readback` je `call_id`; `readback`/`note` | Argumente stehen nur als SHA-256 im Protokoll (Datensparsamkeit); wer den Klartext braucht, muss ihn getrennt aufbewahren und per Hash zuordnen |
| Identifikation der natürlichen Personen, die Ergebnisse verifiziert haben (ausdrücklich nur für Anhang III Nr. 1 lit. a, biometrische Fernidentifizierung) | Art. 12 Abs. 3 lit. d; Art. 14 Abs. 5 | Entscheidung mit Kanal (`by=web|webhook|elicitation`) und Zeitpunkt | `event=decision`, `by`, `note` | v1.1: `by` = `kanal:akteur` – verifiziert nur über `confirm.web.identity_header` hinter einem authentifizierenden Reverse-Proxy; der Formularname ist **selbst erklärt** (`note: self-declared`), der Elicitation-Akteur ist der **Client**, nicht die Person. Zwei-Personen-Prüfung (Art. 14 Abs. 5) gibt es nicht |
| Aufbewahrung der Logs mindestens 6 Monate (Anbieter: Art. 19; Betreiber: Art. 26 Abs. 6); Finanzunternehmen im Rahmen der Finanzaufsichts-Dokumentation | Art. 19 Abs. 1–2; Art. 26 Abs. 6 | Protokoll ist eine Datei, deren Integrität auch nach Monaten prüfbar bleibt (`verify-log` mit öffentlichem Schlüssel) | gesamte Datei + `.head` + `<key>.pub` | Keine Aufbewahrungs-, Archiv- oder Löschfunktion; Rotation startet eine neue Datei. Aufbewahrung ist Betreiberaufgabe |
| Wirksame menschliche Aufsicht während des Betriebs | Art. 14 Abs. 1 | Schreibaktionen werden angehalten, bis ein Mensch entscheidet; Timeout = Ablehnung; ohne konfigurierten Kanal wird abgelehnt (`by=policy`) | `event=decision`, `decision=approve|deny`, `by`, `note=no decision within Ns` | Die Aufsicht ist nur so gut wie die Person vor dem Knopf; agent-gate misst keine Prüfdauer (kein „Durchklick-Detektor“) |
| Fähigkeiten und Grenzen verstehen, Anomalien beobachten | Art. 14 Abs. 4 lit. a | Vorschau in Menschensprache (`summary` aus Vorlage), Regeln je Werkzeug, Rücklesen meldet Abweichungen | `summary`, `readback`, `note` | Vorschau zeigt Argumente, keinen Vorher/Nachher-Diff des Zielsystems (nur das Rücklesen danach) |
| Automation Bias (Neigung, sich auf Ausgaben zu verlassen) bewusst halten | Art. 14 Abs. 4 lit. b | Vorschau zeigt *was* passiert, nicht nur *dass* etwas passiert; `confirm` als Standard für Unbekanntes | `event=preview`, `summary` | Ein lesbarer Satz verhindert Durchklicken nicht; Pflichtbegründung beim Freigeben gibt es nicht (V1) |
| Ausgabe nicht verwenden, überstimmen oder rückgängig machen | Art. 14 Abs. 4 lit. d | `deny` vor Ausführung; `deny`-Regel je Werkzeug; Ablehnung ist der Normalfall bei Timeout | `decision=deny`, `by` | Rückgängigmachen *nach* Ausführung leistet agent-gate nicht – das Rücklesen zeigt nur, ob der Zustand stimmt |
| Eingreifen oder anhalten („Stopp-Taste“) | Art. 14 Abs. 4 lit. e | Jeder schreibende Aufruf hält ohnehin an; Regeldatei kann jedes Werkzeug auf `deny` setzen; Freigabeseite kann geschlossen bleiben (dann Timeout → deny) | `decision=deny`, `by=timeout|policy` | Kein globaler Not-Aus-Schalter im laufenden Betrieb (V1); laufende Upstream-Operationen werden nicht abgebrochen |
| Betreiber überträgt Aufsicht an kompetente Personen mit Befugnis | Art. 26 Abs. 2 | – (organisatorisch) | – | Nicht technisch lösbar; Betreiber dokumentiert Rollen selbst |

## 3. DORA – Verordnung (EU) 2022/2554 (gilt seit 17.01.2025 für Finanzunternehmen)

| Anforderung | Artikel / Quelle + Datum | agent-gate-Funktion | Beleg im Protokoll | Lücke / Grenze |
|---|---|---|---|---|
| Sicherheit und Funktionieren von IKT-Systemen laufend überwachen und kontrollieren | Art. 9 Abs. 1 (Springlex-Wiedergabe ABl. L 333/2022, 17.10.2026) | Jede Schreibaktion eines Agenten läuft durch eine Kontrollstelle mit Protokoll | alle `event`s | Deckt nur den Pfad Agent → Werkzeug; keine Überwachung des Werkzeugs selbst |
| Authentizität, Integrität, Vertraulichkeit von Daten; Schutz vor Verfälschung und Verlust | Art. 9 Abs. 2–3 | Protokoll-Integrität durch Hash-Kette + Signatur; Rücklesen prüft Integrität der *Änderung* (Ist = genehmigt?); Schwärzungs-Hook hält private Daten aus Vorschau/Protokoll | `hash`, `prev`, `sig`, `.head`; `readback=ok` | Schwärzung ist in V1 ein Stub; Vertraulichkeit der Vorschau auf dem Webhook-Weg hängt an TLS des Empfängers (nur https erlaubt) |
| Änderungen an IKT-Systemen werden aufgezeichnet, getestet, bewertet, genehmigt, umgesetzt und verifiziert | Art. 9 Abs. 4 lit. e (Change Management) | Genau diese Kette je Aufruf: aufgezeichnet (`preview`), genehmigt (`decision`), umgesetzt (`result`), verifiziert (`readback`) | `preview → decision → result → readback` | „getestet/bewertet“ im Sinne eines Change-Prozesses leistet agent-gate nicht; es ist ein Laufzeit-Gate, kein Change-Management-System |
| Zugriff auf das zur Funktion Nötige begrenzen | Art. 9 Abs. 4 lit. c | Regeldatei: `allow`/`confirm`/`deny` je Werkzeug; Unbekanntes wird gefragt | `by=rule:<tool>` / `default:<kind>` | Keine Benutzer- oder Rollenverwaltung; Rechte gelten je Proxy-Instanz |
| Anomale Aktivitäten umgehend erkennen; Alarmierung | Art. 10 Abs. 1, 3 | `readback=fehlgeschlagen` (Zielsystem weicht vom Genehmigten ab) und `unklar` sind sofort im Ergebnis und Protokoll sichtbar | `readback`, `note` | Kein Alarmkanal (E-Mail/SIEM) in V1; Erkennung beschränkt sich auf die geprüften Felder der Rücklese-Regel |
| Detektionsmechanismen regelmäßig testen | Art. 10 Abs. 2 | Offline-Demo zeigt Manipulationserkennung reproduzierbar; Testsuite (18 Tests) | – | Der Betreiber muss die Tests in seinen Testzyklus übernehmen |
| IKT-Drittparteienrisiko (externe KI-/MCP-Dienste) | Art. 28–30 | agent-gate liegt *zwischen* Agent und Drittdienst und macht jeden Schreibzugriff sichtbar und freigabepflichtig | `tool` (mit Upstream-Präfix), `args_sha256` | Ersetzt keine Vertragsprüfung, kein Exit-Konzept, keine Register-Pflicht |

## 4. MaRisk – BaFin Rundschreiben 06/2026 (BA) vom 30.06.2026 (9. Novelle)

| Anforderung | Fundstelle / Quelle + Datum | agent-gate-Funktion | Beleg im Protokoll | Lücke / Grenze |
|---|---|---|---|---|
| Funktionstrennung: unvereinbare Tätigkeiten durch verschiedene Mitarbeiter | AT 4.3.1 Tz. 1 (Bundesbank-PDF, 17.10.2026) | Der *Agent* schlägt vor, ein *Mensch* gibt frei – technisch erzwungene Trennung von Veranlassung und Freigabe | `event=preview` (Agent) vs. `event=decision` (Mensch, `by`) | Wer freigibt, wird nicht identifiziert (siehe Art. 12 Abs. 3); ein Agent, der Elicitation selbst beantwortet, hebt die Trennung auf → `confirm.elicitation: false` setzen |
| Risikosteuerungs- und -controllingprozesse: Identifizierung, Beurteilung, Steuerung, Überwachung | AT 4.3.2 Tz. 1 | Regeln je Werkzeug (Steuerung), Rücklesen (Überwachung), Protokoll (Nachweis) | `by=rule:…`, `readback` | Risikobeurteilung (welches Werkzeug ist wie riskant) trifft der Betreiber in der Regeldatei; agent-gate liefert nur Standardwerte aus den MCP-Annotationen und glaubt diesen |
| Verwendung von Modellen, ausdrücklich auch KI; hinreichende Erklärbarkeit | AT 4.3.4 Tz. 1 und Tz. 6 | Vorschau macht die *Handlung* des Modells vor Ausführung lesbar | `summary` | Erklärt nicht, *warum* das Modell die Handlung wählt – nur *was* es tun will |
| Dokumentation systematisch und für sachkundige Dritte nachvollziehbar; Aufbewahrung 5 Jahre | AT 6 Tz. 1 | Protokoll ist Klartext-JSONL mit dokumentiertem Format (`evidence-v1`), für Dritte mit öffentlichem Schlüssel prüfbar | gesamte Datei | Aufbewahrung über 5 Jahre und Lesbarkeit der Schlüssel über die Zeit sind Betreiberaufgabe |
| Technisch-organisatorische Ausstattung an internen Erfordernissen ausrichten; Datenqualität | AT 7.2 Tz. 1–2 | Rücklesen prüft, dass der Zielzustand dem Genehmigten entspricht (Datenqualität der Änderung) | `readback=ok`, `result_sha256` | Nur Felder, die in der Rücklese-Regel stehen |
| Überprüfungen sind zu protokollieren (Notfallkonzept) | AT 7.3 Tz. 4 | – | – | Nicht Gegenstand von agent-gate; genannt, weil ARGONs Recherche „Protokollierung“ pauschal AT 7.2 zuordnete – die einzige wörtliche Protokollierungspflicht steht in AT 7.3 |

## 5. Abweichungen zur ARGON-Recherche (v1.1), gegen Primärquellen geprüft

| ARGON-Aussage | Prüfung | Folge für dieses Dokument |
|---|---|---|
| „Art. 12 und 14 scharf seit 02.08.2026“ (v1.0) bzw. „verschoben auf 02.12.2027 durch Digital Omnibus (EU) 2026/1744“ (v1.1) | **v1.1 bestätigt:** konsolidierte Fassung 27.07.2026 zeigt Art. 113 lit. c (i) 2. Dezember 2027 (Anhang III), (ii) 2. August 2028 (Anhang I), markiert AMENDED; Omnibus-Verweis ABl. L 2026/1744 (`EXTERNAL`, Service-Desk, 17.10.2026) | Daten übernommen |
| „Art. 12 Abs. 2: Logs müssen Zeitraum, Referenzdatenbank, Eingabedaten enthalten“ | **Ungenau:** das steht in Art. 12 **Abs. 3** und gilt nur für Anhang III Nr. 1 lit. a (biometrische Fernidentifizierung); Abs. 2 verlangt allgemein Rückverfolgbarkeit (lit. a–c) | Tabelle trennt Abs. 2 und Abs. 3 |
| „MaRisk 4-Augen-Prinzip“ als Fundstelle | **Nicht wörtlich:** das Rundschreiben nennt „Vier-Augen-Prinzip“ nicht als AT-Regel; die Trennung steht in AT 4.3.1 Tz. 1 (Funktionstrennung) | Fundstelle korrigiert |
| „MaRisk AT 7.2 = Protokollierung“ | **Nicht gedeckt:** AT 7.2 regelt technisch-organisatorische Ausstattung und Datenqualität; die wörtliche Protokollierungspflicht steht in AT 7.3 Tz. 4 (Notfallkonzept); Nachvollziehbarkeit der Dokumentation in AT 6 Tz. 1 | Zeilen entsprechend zugeordnet |
| „DORA Art. 9: unbefugte Datenänderungen verhindern“ | **Sinngemäß, nicht wörtlich:** Art. 9 Abs. 3 nennt Verfälschung/Verlust/unbefugten Zugriff, Abs. 4 lit. e das Change-Management | Wortlaut angepasst |
| „Aufbewahrung 10 Jahre nach Art. 18“ | Art. 18 betrifft die **technische Dokumentation** des Anbieters, nicht die Logs; für Logs gelten Art. 19 / Art. 26 Abs. 6 (mind. 6 Monate) | Nur 6-Monats-Regel übernommen; 10 Jahre hier nicht behauptet |
| Fristen DORA 17.01.2025, MaRisk-Novelle 30.06.2026 | **Bestätigt** (ABl. L 333/2022; Rundschreiben 06/2026 (BA)) | übernommen |
| Bußgelder „bis 15 Mio. EUR / 3 %“, NIS2-Daten, DSGVO Art. 22 | Nicht gegen Primärquelle geprüft | **nicht** in dieses Dokument übernommen (`UNKNOWN` bis geprüft) |

## 6. Was agent-gate bewusst nicht leistet (für das Verkaufsgespräch)

1. **Identität des Freigebenden nur so gut wie der Kanal (v1.1).** Verifiziert ist sie allein über den Reverse-Proxy-Header; Formularname und Webhook-`actor` sind Angaben Dritter, der Elicitation-Akteur ist der Client. Wer Art. 12 Abs. 3 lit. d / Funktionstrennung belegen will, betreibt die Freigabeseite hinter SSO.
2. **Keine Aufbewahrung, kein Archiv, keine Löschfristen.** Datei + Schlüssel aufbewahren ist Betreiberaufgabe.
3. **Kein Alarm-/SIEM-Anschluss.** `readback=fehlgeschlagen` steht im Protokoll und in der Antwort an den Agenten, mehr nicht.
4. **Annotationen werden geglaubt.** Ein Upstream, der `readOnlyHint: true` lügt, bekommt `allow`; Gegenmittel ist eine explizite Regel je Schreibwerkzeug.
5. **Kein Vorher/Nachher-Diff vor der Freigabe**, nur das Rücklesen danach.
6. **Kein Rechtsgutachten.** Dieses Dokument ersetzt keine Einstufung nach Anhang III und keine DORA-/MaRisk-Anwendbarkeitsprüfung.

## 7. Quellen (alle `EXTERNAL`, Abruf 17.10.2026)

- EU-Kommission, AI Act Service Desk, Art. 12, 14, 19, 26, 113 – Text nach EUR-Lex-Konsolidierung CELEX 02024R1689-20260727 (27.07.2026), Änderungen durch „Digital Omnibus on AI“ (ABl. L 2026/1744): https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-12 (…/article-14, …/article-19, …/article-26, …/article-113)
- Verordnung (EU) 2022/2554 (DORA), ABl. L 333 vom 27.12.2022, Art. 9 und 10, Wiedergabe: https://www.springlex.eu/en/packages/dora/dora-regulation/article-9/ und …/article-10/
- BaFin, Rundschreiben 06/2026 (BA) – Mindestanforderungen an das Risikomanagement (MaRisk), Stand 30.06.2026, PDF bei der Deutschen Bundesbank: https://www.bundesbank.de/resource/blob/825336/866a68577eb35afee82fbe60c39a4f87/472B63F073F071307366337C94F8C870/2026-06-30-rundschreiben-data.pdf
- artificialintelligenceact.eu, Art. 14 (Gegenprüfung des Wortlauts und des Anwendungsdatums): https://artificialintelligenceact.eu/article/14/
