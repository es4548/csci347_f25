# incident_report.md
Course: Security Monitoring with SIEM — Week 7
Author: <Your Name>
Date: <YYYY-MM-DD>

## Executive Summary
(Short one-paragraph summary of what you detected and impact.)

Example:
On <DATE> we detected multiple brute-force login attempts from 192.0.2.10 against three user accounts. One account had a successful login after several failures, and the same host later transferred ~120 MB outbound to an external IP. We classified this as a high-priority incident (suspected credential compromise with data exfiltration).

## Evidence & Timeline
- **First detected:** 2025-11-02 10:12:34 UTC — multiple failed logins (5+ attempts) for user `alice` from 192.0.2.10. (See query: Failed login attempts)
- **Follow-up:** 2025-11-02 10:18:00 UTC — successful login for `alice` from 192.0.2.10 shortly after failures.
- **Exfil:** 2025-11-02 10:40:00 UTC — 120,345,600 bytes sent from host 10.1.1.5 to external 198.51.100.25. (See query: High Outbound Volume)

## Detection Queries (used)
- Failed logins: `index=auth_logs action=failed | stats count by user, src_ip | where count >= 5`
- Successful login after failures: see splunk_queries.txt, query #3
- Outbound volume: see splunk_queries.txt, query #5

## Impact Assessment
- Affected user(s): `alice`, `bob`
- Affected host(s): `host-10-1-1-5`
- Data potentially accessed: internal files in `/home/alice/exports` (further forensic analysis required)
- Business impact: potential leakage of confidential project files

## Response & Remediation
- Actions taken:
  1. Suspended `alice` account.
  2. Isolated host `host-10-1-1-5` from network for forensic imaging.
  3. Blocked 192.0.2.10 at perimeter firewall.
  4. Reset credentials for affected accounts and required MFA enrollment.
- Next steps:
  - Full host forensic analysis.
  - Review logs for lateral movement.
  - Update IDS/IPS signatures and add related hashes to threat lookup.

## Lessons Learned
- Need to tune brute-force thresholds and implement blocking at 5 failed attempts.
- Deploy endpoint detection to detect rapid file encryption/writes.

## Attachments / Evidence
- screenshots/dashboard_bruteforce.png
- screenshots/outbound_exfil.png
- splunk saved searches (attach savedsearches.conf snippets if required)
