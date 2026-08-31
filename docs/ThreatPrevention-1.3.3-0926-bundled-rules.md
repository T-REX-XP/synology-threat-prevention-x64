# Threat Prevention 1.3.3-0926 — Bundled rules and alerts

**Package:** ThreatPrevention-cypress-1.3.3-0926  
**Feed:** Emerging Threats Open, Suricata 5.0 tree, **version 9840**  
**Tarball date:** 2021-09-09 (files inside `emerging.rules.tar.gz`)  
**Engine on device:** Suricata 6.0.4 (loads these 5.0-syntax rules after Synology compiles them)

This document is the inventory of every signature shipped in the SPK. The raw files and a machine-readable catalog are in the repo; this page is the analysis.

| Artifact | Path |
| --- | --- |
| Original tarball | `unpacked/package/etc/rules/emerging.rules.tar.gz` (2.9 MiB) |
| Version stamp | `unpacked/package/etc/rules/version.txt` → `9840` |
| Extracted rule files | `extracted/emerging-rules/rules/` (23 MiB, 50 `*.rules` files) |
| Synology custom rule | `unpacked/package/etc/rules/syno-custom-events.rules` |
| Class defaults (drop / disable) | `unpacked/package/etc/rules/signature.conf` |
| Global thresholds | `unpacked/package/etc/suricata/threshold.config` |
| Full catalog (33,723 rows) | `docs/data/bundled-alerts.csv` (14 MiB) |
| Summary JSON | `docs/data/bundled-alerts-summary.json` |
| Parser | `docs/data/parse_rules.py` |

---

## 1. Headline numbers

| Metric | Count |
| --- | --- |
| Signatures parsed (active + commented) | **33,723** |
| **Active** (not commented in the file) | **23,029** |
| Commented out in-file (includes all of `emerging-deleted.rules`) | 10,694 |
| Unique SIDs (no duplicates across files) | 33,723 |
| Active `alert` | 23,028 |
| Active `drop` in the tarball | **0** |
| Active `pass` | 1 (Synology Google Voice exception) |
| Active rules with a CVE reference | 4,234 (983 distinct CVEs) |
| `noalert` flowbit helpers | 1 |

Every ET rule ships as **`alert`**. Inline **drop** is not in the tarball. Synology later rewrites the action from `signature.conf` class policy when it builds `.../suricata/signatures` on the router.

---

## 2. What “bundled” vs “running” means

1. `postinst` unpacks `emerging.rules.tar.gz` into `target/etc/rules/suricata/`.
2. `libsynotps` compiles selected rules into the live signature directory, applying:
   - class `default_action` (`drop` vs alert)
   - class `enabled=no` (rule not loaded)
   - operator self-defined policies
   - the Synology `pass` rule from `syno-custom-events.rules` (always loaded via `suricata.yaml.template`)
3. Live updates replace this snapshot from  
   `https://rules.emergingthreats.net/open/suricata-5.0/` (or ET Pro with an oinkcode).

Until that first successful update, the router inspects traffic with this **September 2021** ET Open snapshot. C2 domains, phishing kits, and CVE coverage from 2022–2026 are **not** in the box.

---

## 3. Synology class policy applied to this snapshot

From `signature.conf`, mapped onto the 23,029 active rules:

| Policy | Classes | Active rules |
| --- | --- | --- |
| **Default drop** | trojan-activity, attempted/successful/unsuccessful-user, attempted/successful-admin, shellcode-detect, web-application-attack, inappropriate-content | **11,103** |
| **Default alert** (inspect, do not drop) | everything else that is enabled | **11,054** |
| **Class disabled** (`enabled=no`) | policy-violation, misc-activity, not-suspicious, others | **872** |

### Default-drop breakdown

| classtype | Priority | Active rules |
| --- | --- | --- |
| web-application-attack | high | 5,307 |
| trojan-activity | high | 3,822 |
| attempted-admin | high | 1,014 |
| attempted-user | high | 850 |
| shellcode-detect | high | 67 |
| successful-admin | high | 25 |
| unsuccessful-user | high | 11 |
| successful-user | high | 7 |
| inappropriate-content | high | **0** (the remaining “inappropriate” rule is tagged `policy-violation` and is disabled) |

### High-severity classes that only alert (not dropped)

These are ET’s newer classtypes (priority 1) that **do not** appear in `signature.conf`. On a stock install they log and notify; they do not drop packets:

| classtype | Active rules | Typical content |
| --- | --- | --- |
| command-and-control | 2,860 | Malware C2 HTTP/DNS/TLS |
| credential-theft | 1,027 | Phish / stealer POST |
| targeted-activity | 945 | APT-style tooling |
| domain-c2 | 912 | Known-bad domains |
| exploit-kit | 402 | EK landing / payload |
| **Total** | **6,146** | |

Reputation IP lists (`drop.rules`, `botcc.rules`, `ciarmy.rules`, `compromised.rules`, `tor.rules`, `3coresec.rules`, `dshield.rules`) are `classtype:misc-attack` → **alert only**, despite names like “ET DROP Spamhaus DROP”. The word DROP in the message is the Spamhaus list name, not a Suricata `drop` action.

---

## 4. Active signatures by file

Commented counts are ET’s own `#alert` disablements plus the entire deleted set. Files with 0 active rules are still in the tarball.

| File | Active | Commented | Role |
| --- | --- | --- | --- |
| emerging-malware.rules | 7,168 | 2,468 | Malware / trojan HTTP+DNS+TLS |
| emerging-web_specific_apps.rules | 4,848 | 748 | App-specific web attacks (largest CVE pile) |
| emerging-deleted.rules | 0 | 3,267 | Retired SIDs, all commented |
| emerging-phishing.rules | 1,807 | 101 | Credential phishing |
| emerging-exploit.rules | 1,114 | 298 | Exploits (mixed CVE) |
| emerging-policy.rules | 806 | 327 | Policy / UA / “interesting” traffic |
| tor.rules | 1,044 | 0 | Tor node IP groups |
| emerging-mobile_malware.rules | 685 | 76 | Android/iOS malware |
| emerging-web_server.rules | 631 | 106 | Generic server attacks |
| emerging-info.rules | 622 | 46 | Informational (includes STUN sid:2033078) |
| emerging-adware_pup.rules | 555 | 585 | PUP / adware |
| emerging-web_client.rules | 516 | 286 | Browser / client-side |
| emerging-exploit_kit.rules | 403 | 800 | Exploit kits (many retired) |
| emerging-netbios.rules | 392 | 82 | SMB/NetBIOS (mostly GPL-converted) |
| emerging-hunting.rules | 355 | 31 | Hunt / suspicious patterns |
| emerging-scan.rules | 281 | 74 | Scanners |
| emerging-user_agents.rules | 242 | 50 | Bad / odd User-Agents |
| emerging-sql.rules | 191 | 120 | SQL injection / DB |
| emerging-activex.rules | 185 | 348 | Legacy IE/ActiveX |
| emerging-ja3.rules | 128 | 5 | TLS JA3 malware hashes |
| emerging-attack_response.rules | 120 | 98 | Post-compromise (id, wget, etc.) |
| ciarmy.rules | 100 | 0 | CINS army IP groups |
| emerging-p2p.rules | 88 | 31 | P2P |
| emerging-rpc.rules | 83 | 34 | RPC |
| emerging-chat.rules | 70 | 20 | IM / chat |
| emerging-dos.rules | 66 | 45 | DoS |
| emerging-shellcode.rules | 62 | 124 | Shellcode buffers |
| emerging-ftp.rules | 57 | 58 | FTP |
| compromised.rules | 56 | 0 | Known-compromised hosts |
| emerging-current_events.rules | 42 | 147 | Time-boxed campaigns (mostly stale/commented) |
| drop.rules | 42 | 0 | Spamhaus DROP IP groups (alert, misc-attack) |
| emerging-dns.rules | 32 | 17 | DNS anomalies |
| botcc.rules | 25 | 0 | abuse.ch botnet C2 IPs |
| emerging-coinminer.rules | 22 | 3 | Cryptominers |
| emerging-misc.rules | 21 | 41 | Misc |
| 3coresec.rules | 20 | 0 | 3CORESec poor-reputation IPs |
| emerging-scada.rules | 18 | 0 | ICS/SCADA |
| emerging-imap.rules | 17 | 16 | IMAP |
| emerging-snmp.rules | 16 | 17 | SNMP (includes sid:2101411) |
| emerging-voip.rules | 16 | 5 | VoIP |
| emerging-icmp_info.rules | 14 | 52 | ICMP info |
| emerging-smtp.rules | 14 | 9 | SMTP |
| emerging-games.rules | 13 | 66 | Games |
| emerging-tftp.rules | 13 | 7 | TFTP |
| emerging-pop3.rules | 9 | 11 | POP3 |
| emerging-worm.rules | 9 | 10 | Worms |
| emerging-telnet.rules | 8 | 2 | Telnet |
| emerging-inappropriate.rules | 1 | 24 | One leftover GPL rule, class policy-violation |
| dshield.rules | 1 | 0 | DShield block list |
| emerging-icmp.rules | 0 | 39 | All commented |
| botcc.portgrouped.rules | 0 | 0 | Header-only; no signatures |
| syno-custom-events.rules | 1 | 0 | Synology `pass` (not in the tarball) |

`sid-msg.map` (4.6 MiB) is a SID→message lookup used by older Barnyard-style pipelines; it is not loaded as detection content. `classification.config` inside the tarball matches the copy Synology also ships at `etc/rules/classification.config`.

---

## 5. Protocol, classtype, SID family

Active rules by decoder / protocol:

| Protocol | Active |
| --- | --- |
| http | 14,794 |
| tcp | 3,338 |
| dns | 2,639 |
| tls | 1,346 |
| udp | 371 |
| ip | 267 |
| smtp | 101 |
| ftp | 59 |
| icmp | 47 |
| smb | 37 |
| tcp-pkt | 27 |
| ssh | 3 |

ET Snort priority mapped to Synology severity (`classification.config`):

| Severity (priority) | Active |
| --- | --- |
| high (1) | 17,791 |
| medium (2) | 4,444 |
| low (3–4) | 794 |

SID families (active):

| Family | SID range | Count | License (per ET LICENSE) |
| --- | --- | --- | --- |
| et-legacy | 2,000,000–2,099,999 | 20,824 | BSD (Emerging Threats) |
| et-other | 2,500,000–2,799,999 | 1,120 | BSD (3CORESec / extra) |
| et-gpl-converted | 2,100,000–2,199,999 | 916 | BSD SIDs, `GPL …` msg prefix (old Snort GPL content) |
| et-open | 2,400,000–2,499,999 | 168 | BSD (DROP / botcc / dshield / tor IP groups) |
| synology-custom | sid:1 | 1 | Synology |

There are **no** remaining original Snort SIDs 1–3464 in the active set (those live only as commented GPL history). Synology reused **sid:1** for its custom pass rule.

Message prefixes (active), useful as a category index:

| Prefix | Count |
| --- | --- |
| ET MALWARE | 7,168 |
| ET WEB_SPECIFIC_APPS | 4,847 |
| ET PHISHING | 1,807 |
| ET EXPLOIT | 1,076 |
| ET TOR | 1,044 |
| ET POLICY | 800 |
| ET MOBILE_MALWARE | 685 |
| ET INFO | 622 |
| ET WEB_SERVER | 605 |
| ET ADWARE_PUP | 555 |
| ET WEB_CLIENT | 516 |
| ET EXPLOIT_KIT | 403 |
| GPL NETBIOS | 356 |
| ET HUNTING | 355 |
| ET SCAN | 269 |
| ET USER_AGENTS | 242 |
| GPL SQL | 190 |

---

## 6. Synology-specific exceptions

### 6.1 Custom pass (sid:1)

`unpacked/package/etc/rules/syno-custom-events.rules` is loaded from `suricata.yaml.template` **in addition to** the compiled ET set:

```
pass udp $HOME_NET any -> 74.125.39.90 [!3478,1023:] (
  msg:"pass traffic to Google Voice server for rule sid:2033078";
  content:"|00 01|"; depth:2; content:"|21 12 a4 42|"; distance:2; within:4;
  reference:url,tools.ietf.org/html/rfc5389;
  classtype:attempted-user; sid:1;
)
```

It is a STUN binding (`0x2112a442`) to a **single Google IP**, meant to suppress false positives from:

- sid:**2033078** — `ET INFO Session Traversal Utilities for NAT (STUN Binding Request On Non-Standard High Port)` (`emerging-info.rules`, classtype `bad-unknown`, default **alert**)

The pass SID collides with historic Snort sid:1; that is safe here because original GPL sid:1 is not active.

### 6.2 Global thresholds (`threshold.config`)

| SID | File | Message | Limit |
| --- | --- | --- | --- |
| 2101411 | emerging-snmp.rules | GPL SNMP public access udp | 1 alert / 60s per destination |
| 2013504 | emerging-policy.rules | ET POLICY GNU/Linux APT User-Agent Outbound | 1 alert / 60s per source |

2013504 is `classtype:not-suspicious` → **disabled** by `signature.conf` anyway (`enabled=no`). The threshold is dead weight unless an operator re-enables that class.

### 6.3 Flowbit helper

sid:**2029986** (`ET EXPLOIT IBM Data Risk Manager Authentication Bypass - Session ID Assignment (set)`) is `noalert` — it only sets flowbits for a follow-up signature.

---

## 7. License

From `extracted/emerging-rules/rules/LICENSE` (Copyright 2003–2021 Emerging Threats):

- SIDs 1–3464 and 100000000–100000908: **GPLv2** (not present as active rules in this snapshot).
- SIDs 2,000,000–2,799,999: **BSD** (Emerging Threats).
- Synology sid:1: Synology copyright (package), not ET.

`gpl-2.0.txt` and `BSD-License.txt` are shipped next to the rules. Redistribution of the extracted tree must keep those notices.

---

## 8. How to query the catalog

```sh
# All active default-drop rules
python3 - <<'PY'
import csv
from pathlib import Path
p = Path("docs/data/bundled-alerts.csv")
with p.open() as f:
    rows = [r for r in csv.DictReader(f)
            if r["disabled_in_file"]=="no" and r["syno_default_action"]=="drop"]
print(len(rows))
for r in rows[:5]:
    print(r["sid"], r["classtype"], r["msg"][:80])
PY

# Rules that mention a CVE
rg -i 'cve,' docs/data/bundled-alerts.csv | wc -l
```

Columns in `bundled-alerts.csv`:

`sid, rev, file, line, action, disabled_in_file, proto, msg, classtype, priority, severity, syno_default_action, syno_enabled, noalert, sid_family, license, cves, references, src, dst, direction, gid, metadata`

`syno_default_action` is **Synology’s class policy**, not the action keyword in the ET file (which is almost always `alert`).

---

## 9. Review notes specific to this ruleset

1. **Five-year-old Open feed.** File timestamps and LICENSE year are 2021. Do not treat this SPK as providing current malware coverage without Package Center / ET auto-update.
2. **C2 and EK do not drop by default.** 6,146 high-priority ET classtypes are alert-only. Operators who expect “IPS drops C2” must add class policies for `command-and-control`, `domain-c2`, `exploit-kit`, `credential-theft`, and `targeted-activity`.
3. **IP reputation lists do not drop.** Spamhaus / DShield / botcc / Tor / CINS are `misc-attack` alerts with 1/hour thresholds in the rule body.
4. **HTTP-heavy.** 14,794 of 23,029 active rules are `http`. TLS is only 1,346 (JA3 + some malware). Encrypted C2 without decryption is largely DNS/IP-list based.
5. **Deleted and commented mass.** 10,694 signatures sit in the tarball but never load (3,267 of them in `emerging-deleted.rules`). They inflate package size and parse time; they are not detections.
6. **Google Voice pass is a single IPv4.** If Google moves STUN off `74.125.39.90`, the exception does nothing and sid:2033078 may fire again — or a later ET revision may change that SID’s meaning.
7. **Engine mismatch.** Rules are Suricata 5.0 ET Open; the binary is 6.0.4. Keyword compatibility is generally fine; newer 6.x-only ET content is not in this tree even after update, because the updater URL is still `/open/suricata-5.0/`.

---

## 10. Reproduce the extract

```sh
mkdir -p extracted/emerging-rules
tar -xzf unpacked/package/etc/rules/emerging.rules.tar.gz -C extracted/emerging-rules
python3 docs/data/parse_rules.py
```

Parser output overwrites `docs/data/bundled-alerts.csv` and `docs/data/bundled-alerts-summary.json`.
