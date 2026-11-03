# 60-second screen recording – command sequence and expected output

**Story:** an AI agent wants to move money. agent-gate (Torwächter) sits between the agent and the bank: the read passes, the
transfer stops for a human, is executed only after approval, read back, and every step lands in a signed log – edit one line
and `verify-log` catches it.

**Setup (off camera):** `pip install -e .` in `products/torwaechter/`; terminal ≈ 100×32, large font. Everything runs
offline against the fake bank in `demo/bank_server.py` (synthetic data). `--keep` leaves the working files behind so the real
CLI can be shown on the tampered log; `--yes` answers the approval question itself – for a live take leave it out and type `y`.

## Take 1 – approve (≈ 45 s)

```sh
torwaechter demo --yes --keep /tmp/tw-demo
```
Expected output (ids and paths vary):
```text
▶ Tools behind the gate: kontostand, ueberweisung

▶ 1) Read-only call `kontostand` → passes through without questions
    Saldo: 1250.00 EUR | gate: allowed

▶ 2) Writing call `ueberweisung` → preview, your decision, execution, read-back

┌─ Torwächter asks ─────────────────────────────
│ Torwächter: Transfer 120.5 EUR to Demo GmbH
│ Tool: ueberweisung
│ Arguments: {"an": "Demo GmbH", "betrag": 120.5, "zweck": "Rechnung 42"}
└───────────────────────────────────────────────
Approve? [y/N] y   (scripted)
    Überwiesen: 120.50 EUR an Demo GmbH | gate: {"status": "executed", "id": "tw-…", "approved_by": "elicitation", "readback": "ok", "readback_detail": "read-back matches"}

▶ 3) Balance after: Saldo: 1129.50 EUR

▶ 4) verify-log: OK – 8 signed, chained entries in torwaechter-audit.jsonl
    #1 allow     kontostand    allow    rule:kontostand
    #2 result    kontostand                                 passthrough
    #3 preview   ueberweisung  confirm  rule:ueberweisung
    #4 decision  ueberweisung  approve  elicitation
    #5 result    ueberweisung                               ok
    #6 readback  ueberweisung                        ok     read-back matches
    #7 allow     kontostand    allow    rule:kontostand
    #8 result    kontostand                                 passthrough

▶ 5) Someone rewrites entry #4 – the decision – so it looks as if a human never approved …
    verify-log: TAMPERED – line 4: hash mismatch (entry modified)

▶ Done. Working files are in /tmp/tw-demo – try: torwaechter verify-log --config /tmp/tw-demo/torwaechter.yaml
```

Then, on camera, the real verifier on the tampered file:
```sh
torwaechter verify-log --config /tmp/tw-demo/torwaechter.yaml
```
```text
TAMPERED: 8 entries, 1 problem(s)
  line 4: hash mismatch (entry modified)
```
(exit code 2). Optional extra 5 s – remove the sidecar and show that the verifier no longer gives a clean verdict:
```sh
rm /tmp/tw-demo/torwaechter-audit.jsonl.head && torwaechter verify-log --config /tmp/tw-demo/torwaechter.yaml
```
```text
TAMPERED: 8 entries, 1 problem(s), 1 warning(s)
  line 4: hash mismatch (entry modified)
  warning: head sidecar missing: truncation at the end of the log cannot be ruled out
```

## Take 2 – deny (≈ 15 s, alternative ending)

```sh
torwaechter demo --no
```
```text
Approve? [y/N] n   (scripted)
    Not approved (elicitation): Transfer 120.5 EUR to Demo GmbH | gate: {"status": "denied", "id": "tw-…", "reason": "elicitation: action=accept"}

▶ 3) Balance after: Saldo: 1250.00 EUR
```
Nothing executed, balance unchanged, and the preview + denial are still in the log (`preview`, `decision deny`).

## What to say (one line per step)

| t | Screen | Say |
|---|---|---|
| 0–5 s | `torwaechter demo …` | "An AI agent wants to use a bank. agent-gate sits in between." |
| 5–12 s | step 1 `gate: allowed` | "Reading is harmless – it passes through. Logged, not stopped." |
| 12–30 s | the boxed question, `y` | "Writing stops. Preview: what, to whom, how much. Only a human unblocks it." |
| 30–37 s | `"readback": "ok"` | "After executing, the gate reads the balance back. 'Done' only with proof." |
| 37–50 s | step 4 (8 entries) → step 5 `TAMPERED – line 4` | "Every step is in a hash-chained, signed log. Rewrite who approved – caught." |
| 50–58 s | `torwaechter verify-log …` → `TAMPERED` | "Anyone with the public key can verify. No trust in the operator needed." |
| 58–60 s | README headline | "Preview, confirm, execute, read back, prove. Any MCP tool, any client." |

The same sequence runs in CI (`.github/workflows/tests.yml`, job `torwaechter`), so the expected output above is checked on every push.
