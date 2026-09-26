# Bringing StealthTap up on a new network

False positives are a property of the network, not just of the software: every site has its own broadcast chatter, update
mechanisms, long-lived vendor connections and engineering traffic. The rules and models were tuned on real traffic from a small number
of networks (`docs/PRD.md` §14), so a new site needs a calibration pass before its alerts are trusted. This is that procedure.

## 1. Observe for a day, alert on nothing
Attach the sensor at the mirror port / TAP (or gateway) and let it run 24 h over a normal working cycle. Record the same traffic for
review (the sensor's packet ring is bounded, so record with `scripts/collect_live_pcap.py --minutes 1440` or your own mirror recorder).

## 2. Triage the groups, not the alerts
```
python scripts/site_calibration.py <capture files or folders> --recursive --name mysite --allowlist-out allowlist.suggested.json
```
Writes `docs/reports/site_calibration_mysite.{json,md}`: alerts **grouped** by (class, detection mode, destination port, evidence
signature) with how many captures, source hosts and destination hosts each group touches, plus an example. A false-positive pattern shows
up as one big group; a real finding as a small, odd one. `allowlist.suggested.json` has one *disabled* entry per group.

For each group ask: what is it? who owns the hosts? is it expected here? Then:

| Verdict | Action |
|---|---|
| Real finding | leave it; investigate |
| Known-benign at this site (e.g. the engineering workstation programming its PLC, a backup job's big upload) | allowlist it (step 3) |
| Wrong for every site (a rule misfiring on a common protocol) | do **not** allowlist — file it as a bug with the example and the capture; that is how the fixes in `docs/PRD.md` §14.3 were found |

## 3. Allowlist what a human verified (`config/allowlist.json`)
Copy `config/allowlist.example.json`. Rules match on class, severity, mode, source/destination address or CIDR, ports and evidence fields;
every rule needs a `reason`, may carry an `expires` date, and cannot be a blanket "suppress this class" (`src/allowlist.py` refuses such
rules and reports why at `GET /capture/allowlist`). CRITICAL alerts are never suppressed unless the rule sets `"critical_ok": true`.
Suppressed alerts are **counted and reviewable** (`GET /capture/suppressed`, and `suppressed_by_allowlist` on uploads), never silently
dropped. The file is re-read automatically.

## 4. Decide the ML question with this site's own numbers
The flow and Modbus ML models are corroboration-only by default (`ML_FLOW_STANDALONE_CONFIDENCE`, `ML_MODBUS_STANDALONE_CONFIDENCE`).
To consider enabling the flow model alone, run `scripts/flow_model_operating_points.py --benign <this site's capture> ...` and read the
false-positive rate at your chosen threshold; if you have thousands of benign flows from this site, `scripts/retrain_flow_real_benign.py`
retrains with them (measured effect on the reference network: 23.7% → ~0%).

## 5. Then go live and review weekly
Re-run the calibration on each week's recording for the first month; new groups are either new behaviour on the network or something the
allowlist should not have hidden (check `GET /capture/suppressed` and the audit log). Send anything that looks like a rule bug upstream
with the capture excerpt.

## What this does and does not guarantee
It gets the false-alarm rate on **your** network measured and under your control. It does not make the rules right for networks nobody has
tested: the first calibration on a new site is expected to find new groups. The reference results (23 false positives → 1 on the Wi-Fi
capture, ICS captures from 343 public sites: 1 generic-engine alert in 5,497 flows) are in `docs/PRD.md` §14 and
`docs/reports/site_calibration_ics_public_sites.md`.
