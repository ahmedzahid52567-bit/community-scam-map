# Community Scam Map

**In simple words:** People warn each other about scam phone numbers, UPI IDs and links, and check one before they trust it. Example from the brief: Ravi's father loses ₹2 lakh to a fake "digital arrest" call. Ravi reports the number. Next day Priya checks the same number and sees "Reported by 7 people near you" — so she does not trust it.

## Run it (2 minutes, no npm install)

```bash
node server.js
# open http://localhost:3000
```

Node.js only, no dependencies. `PORT` is read from the environment (Render sets it automatically).

## The 7 API addresses (exactly as the PRD appendix)

| Method | Address | What it does |
|---|---|---|
| GET | /health | `{"ok": true}` |
| POST | /reports | One scam report → 201, 400 for junk, 429 for rate-limit |
| GET | /lookup?type=phone&value=... | KNOWN_SCAM / SUSPICIOUS / NO_REPORTS / VERIFIED_BUSINESS |
| GET | /map?pincode=...&days=7&radius_km=2 | Clusters for the last 7 days, by area |
| GET | /alerts?pincode=... | SPIKE + NEW_TYPE alerts |
| POST | /admin/reset | Deletes all reports |
| POST | /challenges | Business dispute → under_review, never KNOWN_SCAM while under review |
| GET/POST | /license | Licence status / upload a new licence |

## How a number is normalised (one identifier, many spellings)

- Phone: `+91 98765 43210`, `09876543210`, `98765-43210`, `919876543210` → `+919876543210`. Short helplines (`1930`, `1909`) and toll-free (`1800…`, `1860…`) are kept as-is.
- UPI: lower case, no spaces — `Ravi12@OKAXIS` → `ravi12@okaxis`.
- Link: `https://`, no `www.`, nothing after `?`, no trailing `/`.
- SMS sender: `VM-HDFCBK`, `AD-HDFCBK` → `HDFCBK`.

Why: without this, the same scammer typed two ways would look like two different numbers, and the judges' format test would fail.

## Trust rules — how fake reports are stopped (and real ones are not)

A report only *counts* if it is new on all three checks below. The rest are still stored (so `report_count` is honest), but they do not raise `distinct_reporters` and do not trigger map/alerts.

1. **One reporter = one count.** Same `reporter_id` for one identifier counts once, even if sent 6 times. Why: one angry person must not label someone.
2. **One internet connection = one count.** Same `ip_prefix` for one identifier counts once. Why: this stops 22 fake accounts made on one Wi-Fi.
3. **One copied description = one count.** The same exact note text for one identifier counts once. Why: this stops 40 friends copy-pasting the same report to bomb a real bakery. Empty notes are *not* collapsed this way, so real reports with no note still count.
4. **Junk is rejected (400).** `12345`, `test`, bad area codes, bad dates.

Verdict: trusted count ≥ 5 → KNOWN_SCAM; 1–4 → SUSPICIOUS; 0 → NO_REPORTS. Verified numbers always win over reports. A disputed number under review can never be KNOWN_SCAM.

Why not a higher threshold? A real scam in the brief's example has 7 reporters. 5 lets a real wave pass while a single trick (which collapses to 1) cannot pass. Why not count every report? Then every trick above would work.

## Privacy — the 5 rules, built in

1. Only the **area** (pincode/locality from the 25-area list) is saved, never an exact location. Map points are the fixed area points, never a reporter's GPS.
2. Numbers are **masked until 3 trusted reporters**: phone `98XXXXX210`, UPI `r***@okaxis`, link `sbi***.in/...`, sender `HD****`.
3. Wording is **"Reported by 7 people near you"**, never "This person is a fraud".
4. No names, social-media or people-search data are collected. Evidence in lookup never includes reporter, IP or note.
5. No personal data in logs.

## Map and alerts

- Map: trusted reports in the last 7 days (from `occurred_at`, vs the server clock), grouped by area point, within `radius_km` of the requested area. Severity: ≥10 CRIT, ≥4 HIGH, else MED.
- SPIKE: trusted reports in the last 24h are ≥5 **and** at least double the daily average of the 7 days before.
- NEW_TYPE: a scam type in the last 24h that was not seen in that area in the 30 days before.
- Fake reports (collapsed by the trust rules) never trigger map counts or alerts.

## Licence — how it works, and the live demo

- The server holds only the **public key** (`server.js`). The **private key** (`license-private-key.pem`) stays on the team laptop and is in `.gitignore` — never commit it.
- A licence file is `{licensee, expires_at, signature}` where signature = Ed25519 signature of `licensee|expires_at`. Editing the date breaks the signature → upload returns `400 INVALID_SIGNATURE`.
- The server checks the licence on **every API request** except `GET /health` and `GET/POST /license`. Expired → `403 {"error":"LICENSE_EXPIRED"}`. The frontend then shows "Licence expired. Contact your provider." **No data is deleted.**
- Renewal: `POST /license` with a new signed file works **without restarting** — old data is still there immediately.
- Clock-rollback guard: the server saves the latest time it has seen (`lastSeenMs` in `data.json`). If the clock jumps backwards by more than 5 minutes, the licence is treated as invalid. Why: otherwise setting the clock back a year would revive an expired licence.

### Make the two demo licences (do the 5-minute one just before the demo)

```bash
# long licence (already in licence-long.json, expires 2027-12-31)
node tools/sign-license.js --licensee "Demo Bank" --expires "2027-12-31T23:59:00+05:30" --key license-private-key.pem --out licence-long.json

# 5-minute licence — REGENERATE this at demo time, or it will already be expired
node tools/sign-license.js --licensee "Demo Bank" --minutes 5 --key license-private-key.pem --out licence-5min.json
```

### Live demo, in order

1. Show the app working + `GET /license` (who + when it expires).
2. Upload the 5-minute licence (paste it in the app's Licence section, or `POST /license`).
3. Wait 5 minutes → a lookup fails with 403 and the app shows the expired screen.
4. Upload the long licence → the app works again within a minute, old data still there, no restart.

## Deploy on Render (free, HTTPS)

1. Push this folder to a public GitHub repo.
2. Render → New → Web Service → pick the repo. Build: `echo no-build-needed`, Start: `node server.js`. Free plan is fine.
3. Your URL will be like `https://community-scam-map.onrender.com`. Test `/health` and `/license` on that URL, not on localhost.
4. **Before judging, regenerate the long licence if needed and make sure `license.json` in the repo is valid** — the server starts from that file.

## Verified numbers, scam types, channels

All 19 verified entries, 12 scam types and 6 channels from Appendix C are in `server.js` / the app. Unknown scam types are accepted as `other`, not rejected.

## Test results (local, 31 Oct 2026)

- Real scam, 7 diverse reporters, 7 spellings of one number → KNOWN_SCAM, distinct 7, all spellings give the same answer.
- Junk `12345` → 400. One person ×6 → distinct 1, SUSPICIOUS. 22 accounts, one Wi-Fi → distinct 1. 40 friends, same copied note → distinct 1. None became KNOWN_SCAM.
- 2 reports only → number masked (`+91 66XXXXX444`), SUSPICIOUS.
- Verified: `1930`, Fresh Bakes `+91 80 4100 2233`, `freshbakes@okaxis` → VERIFIED_BUSINESS.
- Dispute → lookup shows `challenged: true` and drops from KNOWN_SCAM to SUSPICIOUS.
- Licence: expired file → lookup 403 LICENSE_EXPIRED, health still OK; long file uploaded → works again, old data kept, no restart; tampered date → INVALID_SIGNATURE; lookup time ~8 ms (< 500 ms required).
