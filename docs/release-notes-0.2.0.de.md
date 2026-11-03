# lookfirst 0.2.0 — Release-Notes (Entwurf)

**Stand:** vor 1.0, kein Produktionsrelease. Apache-2.0. Python-Paket `lookfirst`.

## Was es ist
Eine Schleuse zwischen KI-Agenten und ihren Werkzeugen (MCP-Proxy). Vor einem riskanten Werkzeugaufruf: Vorschau, was passiert → ein Mensch bestätigt (im Client, auf einer lokalen Webseite oder per Webhook) → Rücklesen des Ergebnisses → signiertes Prüfprotokoll.

## Was in 0.2.0 steckt
- Vorschau, Bestätigung (drei Kanäle), Rücklesen, signiertes Prüfprotokoll (`verify-log`).
- Schutz vor gefälschter Vorschau: Steuer-, Bidi-, Zero-Width-, leer wirkende und weitere unsichtbare Zeichen erscheinen in jedem Kanal als `\uXXXX`; gegen alle Default-Ignorable-Zeichen geprüft.
- Webhook-Inhalte tragen maskierte `tool_display` / `arguments_display`; Empfänger müssen diese zeigen, nicht die Rohfelder.
- Tests: 148 (5 dokumentierte erwartete Fehlschläge, die die bekannten Grenzen festhalten).

## Bekannte Grenzen (siehe README)
B4.1 Kürzen des Protokolls bei gelöschter `.head`; B5.1/B5.2 Geheimnis-Schwärzung unvollständig (z. B. `db_password`, `access_token`); B7.1 Selbstfreigabe durch autonome Clients, die die Freigabeseite erreichen. Homoglyphen werden nicht erkannt.

## Belege
Unit-Tests und unabhängige Gegenprüfung durch ein zweites Modell (lokale Läufe). Ein aufgezeichneter Lauf mit einem echten Client steht aus und wird hier **nicht** behauptet.

## Installation
`pip install lookfirst` (sobald veröffentlicht) oder aus Wheel/Quellpaket am Release.
