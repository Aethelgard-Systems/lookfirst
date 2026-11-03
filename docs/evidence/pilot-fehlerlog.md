# lookfirst: Pilot-Fehlerlog

Stand: 29.10.2026. Ein Livebeginn des lokalen Piloten ist nicht belegt (UNKNOWN).
Die leere Tabelle bedeutet nicht „fehlerfreier Pilot“. Synthetische Prüfungen
und Reviewbefunde zählen nicht als echte Pilotvorgänge.

## Echte Pilotvorgänge

Jeden Vorfall am selben Tag erfassen, auch wenn lookfirst korrekt gestoppt
oder abgelehnt hat. Keine Tokens, Serverpfade oder privaten Aufgabentitel
aufnehmen. Folgen und Abhilfe nur mit Beleg beschreiben.

| Datum | Was passierte? | Was lookfirst tat (gestoppt/abgelehnt/Zeitablauf/Fehler) | Folge | Fix/PR |
|---|---|---|---|---|

## Reviewbefunde vor dem Pilot

Diese Einträge dokumentieren Entwicklungsfehler, keine Livevorfälle.
Evidenz: DIRECT_EVIDENCE aus Code und synthetischen Prüfungen.

| Datum | Was passierte? | Was lookfirst tat | Folge | Fix/PR |
|---|---|---|---|---|
| 26.10.2026 (Reviewbeleg) | Die Titel-Deduplizierung hatte keine zeitliche Grenze (M1). | Eine spätere gleichnamige Aufgabe hätte die alte Erfolgsmeldung erhalten. | Berechtigte neue Aufgaben konnten unterdrückt werden; kein Livevorfall belegt. | [#610, Fix 39a8ac1](https://github.com/marcogernand-hub/aethelgard-core/pull/610/commits/39a8ac1): auf 600 Sekunden begrenzt, Wiederholung ausdrücklich gekennzeichnet. |
| 27.10.2026 (Reviewbeleg) | Der Adapter verwendete einen falschen API-Vertrag. | Die Implementierung zielte auf Version 1 mit PUT statt auf den bestehenden Version-2-Vertrag mit POST. | Echte Anlage war damit nicht nachgewiesen; kein Live-Schreibversuch durch WORK. | [#610, Fix 0060f7d](https://github.com/marcogernand-hub/aethelgard-core/pull/610/commits/0060f7d): an vorhandenen Vertrag angepasst; sieben synthetische Prüfungen bestanden. |

## Abschluss

Nach dem echten Pilot: Zeitraum, Anzahl echter Vorgänge, Anzahl Vorfälle und
verbleibende offene Punkte mit Belegen an UWE übergeben. Bis dahin sind diese
Werte UNKNOWN; Reviewzeilen nicht als Pilotstatistik zählen.
