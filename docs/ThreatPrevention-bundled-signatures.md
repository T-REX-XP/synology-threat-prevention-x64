# Bundled Threat Prevention signatures

**Package:** Threat Prevention 1.3.3-0926 (Cypress)  
**Feed:** Emerging Threats Open **version 9840**, Suricata **5.0** tree  
**Newest rule metadata:** 2021-09-08  
**Extracted:** 2026-08-31 from `etc/rules/emerging.rules.tar.gz` plus `syno-custom-events.rules`

This note catalogs every signature shipped in the SPK. The engine (`synosuricata` 6.0.4) does **not** load this tarball as `drop` rules. Almost every bundled line is `alert`; Synology compiles class defaults from `signature.conf` into the live `signatures/` tree at install/update time.

---

## 1. Where the files are

CSV/JSON catalogs under `docs/rules/` (except `summary.json`) are **generated**
(`extract_rules.py`) and are not in git. Official tarball paths below exist
after `./build.sh` extracts the public SRM SPK.

| Path | Contents |
| --- | --- |
| `unpacked/package/etc/rules/emerging.rules.tar.gz` | Vendor tarball (2.9 MiB) |
| `unpacked/package/etc/rules/extracted/rules/` | Full extract (49 `*.rules` files + licenses + `sid-msg.map`) |
| `unpacked/package/etc/rules/syno-custom-events.rules` | One Synology pass rule (copied into extract) |
| `unpacked/package/etc/rules/signature.conf` | Class → drop / disable policy |
| `unpacked/package/etc/suricata/threshold.config` | Two SID rate limits |
| `docs/rules/alerts-active.csv` | **23,027** enabled signatures (one row each) |
| `docs/rules/alerts-all.csv` | **33,715** unique SIDs including commented/deleted |
| `docs/rules/alerts-active.json` | Compact JSON of the enabled set |
| `docs/rules/summary.json` | Aggregates used below |
| `docs/rules/extract_rules.py` | Reproducible parser |

Regenerate catalogs:

```sh
python3 docs/rules/extract_rules.py
```

Do not paste the 23k-row CSV into this document. Filter it, for example:

```sh
# Every SID Synology would drop by class default
python3 -c "import csv; rows=csv.DictReader(open('docs/rules/alerts-active.csv'));
print('\n'.join(r['sid']+' '+r['msg'] for r in rows if r['syno_default_action']=='drop' and r['syno_class_enabled']=='yes'))"
```

---

## 2. Headline counts

| Set | Count | Notes |
| --- | --- | --- |
| Parsed rule lines | 33,715 | Unique SIDs; no duplicates across files |
| Enabled in the tarball | **23,027** | Loaded unless the class is disabled |
| Commented / deleted | 10,688 | `emerging-deleted.rules` (3,266) plus in-file `#alert` |
| Action `alert` | 23,026 | ET ships detect-only |
| Action `pass` | 1 | Synology Google Voice STUN exception |
| Action `drop` in tarball | **0** | Drops are a Synology compile step |
| With a CVE reference | 4,233 | 982 distinct CVE ids |
| GPLv2 (ET-GPL, SID 210xxxx) | 916 | Converted Snort GPL |
| BSD Emerging Threats | 22,110 | SID 2,000,000–2,799,999 |
| Synology custom | 1 | SID 1 |

Snort classification priority (1 = high):

| Severity | Count | Share of enabled |
| --- | --- | --- |
| High (priority 1) | 17,790 | 77.3% |
| Medium (priority 2) | 4,443 | 19.3% |
| Low (priority 3–4) | 794 | 3.4% |

Protocol of enabled rules: HTTP 14,792 · TCP 3,338 · DNS 2,639 · TLS 1,346 · UDP 371 · IP 267 · SMTP 101 · FTP 59 · ICMP 47 · SMB 37 · tcp-pkt 27 · SSH 3.

---

## 3. What Synology actually does with these alerts

`etc/rules/signature.conf` maps **classtype** → default IPS action. That mapping is what operators see as “Drop high-risk packets automatically.”

| Class | `signature.conf` | Enabled rules | Effect |
| --- | --- | --- | --- |
| trojan-activity | drop | 3,821 | Drop |
| attempted-user / unsuccessful-user / successful-user | drop | 868 | Drop |
| attempted-admin / successful-admin | drop | 1,039 | Drop |
| shellcode-detect | drop | 67 | Drop |
| web-application-attack | drop | 5,307 | Drop |
| inappropriate-content | drop | 0 | No enabled rules use this class |
| policy-violation | drop **and** `enabled=no` | 542 | **Not loaded** |
| misc-activity | `enabled=no` | 267 | **Not loaded** |
| not-suspicious | `enabled=no` | 63 | **Not loaded** |
| others (unlisted classes) | (inherit alert) | rest | Alert only |

**At runtime, with stock `signature.conf`:**

| Outcome | Count |
| --- | --- |
| Would **drop** | 11,101 |
| Would **alert** (log, do not block) | 11,053 |
| Class **disabled** (not in the compiled set) | 872 |
| Pass exception | 1 |

Self-defined policies in the UI override this per SID / class / IP pair.

### IP-reputation lists do not drop

ET files named DROP / CINS / Tor / Spamhaus are `classtype:misc-attack`. That class is **not** in the drop list, so they only alert:

| File | Enabled SIDs | syno_drop | Typical msg |
| --- | --- | --- | --- |
| `tor.rules` | 1,044 | 0 | ET TOR Known Tor Relay/Exit Node |
| `ciarmy.rules` | 100 | 0 | ET CINS Active Threat Intelligence |
| `compromised.rules` | 56 | 0 | ET COMPROMISED Known Compromised Host |
| `drop.rules` | 42 | 0 | ET DROP Spamhaus DROP Listed Traffic |
| `3coresec.rules` | 20 | 0 | ET 3CORESEC Poor Reputation IP |
| `dshield.rules` | 1 | 0 | ET DSHIELD |
| `botcc.rules` | 25 | 25 | Botnet C2 — classtype **trojan-activity**, so these **do** drop |

About **18,967** IP/CIDR members are packed into those grouped `alert ip [a,b,c,...]` lines. They are a reputation feed, not a blocklist, unless an operator adds a policy.

---

## 4. Enabled rules by file

| File | Enabled | Class-drop | Class-disabled | CVE refs | Role |
| --- | --- | --- | --- | --- | --- |
| emerging-malware.rules | 7,168 | 2,889 | 12 | 19 | Trojans, stealers, loaders |
| emerging-web_specific_apps.rules | 4,847 | 4,827 | 0 | 3,252 | App/CMS/plugin CVEs |
| emerging-phishing.rules | 1,806 | 32 | 17 | 0 | Credential phishing (mostly alert) |
| emerging-exploit.rules | 1,114 | 1,025 | 11 | 452 | Exploit / RCE |
| tor.rules | 1,044 | 0 | 0 | 0 | Tor relays (alert) |
| emerging-policy.rules | 806 | 79 | 388 | 10 | Policy / UA / crypto; many disabled |
| emerging-mobile_malware.rules | 685 | 243 | 0 | 0 | Android/iOS malware |
| emerging-web_server.rules | 631 | 494 | 3 | 69 | Generic web-server attacks |
| emerging-info.rules | 622 | 86 | 113 | 4 | Informational (incl. STUN sid 2033078) |
| emerging-adware_pup.rules | 555 | 2 | 2 | 0 | PUP (mostly alert) |
| emerging-web_client.rules | 516 | 331 | 15 | 99 | Browser / client exploits |
| emerging-exploit_kit.rules | 403 | 1 | 0 | 7 | Exploit kits (alert; classtype exploit-kit) |
| emerging-netbios.rules | 392 | 113 | 0 | 184 | SMB/NetBIOS, mostly GPL |
| emerging-hunting.rules | 355 | 88 | 67 | 1 | Hunt / suspicious patterns |
| emerging-scan.rules | 281 | 77 | 27 | 4 | Scanners |
| emerging-user_agents.rules | 242 | 149 | 19 | 0 | Bad / malware UAs |
| emerging-sql.rules | 191 | 186 | 0 | 6 | SQL injection |
| emerging-activex.rules | 185 | 183 | 0 | 8 | ActiveX |
| emerging-ja3.rules | 128 | 1 | 0 | 0 | TLS JA3 hashes |
| emerging-attack_response.rules | 120 | 47 | 2 | 1 | Compromise indicators |
| ciarmy.rules | 100 | 0 | 0 | 0 | CINS poor-reputation IPs |
| emerging-p2p.rules | 88 | 8 | 80 | 0 | P2P; classtype often policy-violation (disabled) |
| emerging-rpc.rules | 83 | 12 | 0 | 34 | RPC |
| emerging-chat.rules | 70 | 1 | 69 | 0 | Chat; mostly disabled classes |
| emerging-dos.rules | 66 | 5 | 1 | 11 | DoS |
| emerging-shellcode.rules | 62 | 60 | 0 | 0 | Shellcode (drop) |
| emerging-ftp.rules | 57 | 31 | 2 | 30 | FTP |
| compromised.rules | 56 | 0 | 0 | 0 | Compromised hosts |
| drop.rules | 42 | 0 | 0 | 0 | Spamhaus DROP (alert) |
| emerging-current_events.rules | 42 | 42 | 0 | 0 | Current-event malware |
| emerging-dns.rules | 32 | 9 | 4 | 2 | DNS |
| botcc.rules | 25 | 25 | 0 | 0 | Botnet C2 (drop) |
| emerging-coinminer.rules | 22 | 1 | 0 | 0 | Coin miners |
| emerging-misc.rules | 21 | 6 | 0 | 6 | Misc |
| 3coresec.rules | 20 | 0 | 0 | 0 | 3CORESEC IPs |
| emerging-scada.rules | 18 | 14 | 0 | 4 | ICS/SCADA |
| emerging-imap.rules | 17 | 2 | 0 | 6 | IMAP |
| emerging-snmp.rules | 16 | 4 | 0 | 11 | SNMP (incl. sid 2101411) |
| emerging-voip.rules | 16 | 0 | 1 | 1 | VoIP |
| emerging-icmp_info.rules | 14 | 0 | 14 | 0 | ICMP info (disabled class) |
| emerging-smtp.rules | 14 | 3 | 4 | 5 | SMTP |
| emerging-games.rules | 13 | 0 | 12 | 0 | Games (disabled) |
| emerging-tftp.rules | 13 | 5 | 7 | 1 | TFTP |
| emerging-pop3.rules | 9 | 9 | 0 | 5 | POP3 |
| emerging-worm.rules | 9 | 7 | 0 | 1 | Worms |
| emerging-telnet.rules | 8 | 4 | 0 | 0 | Telnet |
| dshield.rules | 1 | 0 | 0 | 0 | DShield blocklist |
| emerging-inappropriate.rules | 1 | 0 | 1 | 0 | Inappropriate content |
| syno-custom-events.rules | 1 | n/a | 0 | 0 | Pass Google Voice STUN |

Files with **no enabled rules** (headers / commented only): `emerging-deleted.rules`, `emerging-icmp.rules`, `botcc.portgrouped.rules`.

`sid-msg.map` is a SID → message index (33,713 lines), not loaded as detection.

---

## 5. Classification breakdown (enabled)

| classtype | Count | Snort priority | Stock Synology action |
| --- | --- | --- | --- |
| web-application-attack | 5,307 | high | drop |
| trojan-activity | 3,821 | high | drop |
| command-and-control | 2,860 | high | **alert** (not in signature.conf) |
| misc-attack | 1,335 | medium | **alert** (IP lists live here) |
| bad-unknown | 1,099 | medium | alert |
| credential-theft | 1,027 | high | **alert** |
| attempted-admin | 1,014 | high | drop |
| targeted-activity | 945 | high | **alert** |
| domain-c2 | 912 | high | **alert** |
| attempted-user | 850 | high | drop |
| social-engineering | 799 | medium | **alert** |
| pup-activity | 558 | medium | **alert** |
| policy-violation | 542 | high | disabled |
| exploit-kit | 402 | high | **alert** |
| protocol-command-decode | 317 | low | alert |
| misc-activity | 267 | low | disabled |
| attempted-recon | 259 | medium | alert |
| unknown | 119 | low | alert |
| attempted-dos | 91 | medium | alert |
| external-ip-check | 74 | medium | alert |
| web-application-activity | 69 | medium | alert |
| shellcode-detect | 67 | high | drop |
| not-suspicious | 63 | low | disabled |
| rpc-portmap-decode | 60 | medium | alert |
| coin-mining | 44 | medium | alert |
| successful-admin | 25 | high | drop |
| network-scan | 18 | low | alert |
| suspicious-login | 13 | medium | alert |
| denial-of-service | 12 | medium | alert |
| successful-recon-limited | 11 | medium | alert |
| unsuccessful-user | 11 | high | drop |
| string-detect | 10 | low | alert |
| suspicious-filename-detect | 10 | medium | alert |
| successful-user | 7 | high | drop |
| default-login-attempt | 5 | medium | alert |
| non-standard-protocol | 2 | medium | alert |
| system-call-detect | 1 | medium | alert |
| successful-recon-largescale | 1 | medium | alert |

Newer ET classes (`command-and-control`, `domain-c2`, `credential-theft`, `exploit-kit`, `targeted-activity`) are **high severity in ET metadata** but **not dropped** unless the operator adds a class or SID policy. That is the main gap between “high-risk packet drop” marketing and the compiled ruleset.

---

## 6. Custom rule and rate limits

### Synology pass (SID 1)

```
pass udp $HOME_NET any -> 74.125.39.90 [!3478,1023:] (
  msg:"pass traffic to Google Voice server for rule sid:2033078";
  content:"|00 01|"; depth:2; content:"|21 12 a4 42|";
  classtype:attempted-user; sid:1;
)
```

This carves out STUN to a single Google IP so **SID 2033078** (`ET INFO Session Traversal Utilities for NAT (STUN Binding Request On Non-Standard High Port)`, also `attempted-user` → drop) does not kill Google Voice. SID 1 sits in the historic GPL range; it is Synology-local, not an ET rule.

### Global thresholds (`threshold.config`)

| SID | Message | Class | Limit |
| --- | --- | --- | --- |
| 2101411 | GPL SNMP public access udp | attempted-recon (alert) | 1 event / 60s / destination |
| 2013504 | ET POLICY GNU/Linux APT User-Agent Outbound | not-suspicious (**class disabled**) | 1 / 60s / source |

2013504 is already in a disabled class, so the threshold is leftover noise control.

---

## 7. Age of the bundled feed

Rule `created_at` / `updated_at` metadata (enabled set):

| Year | Created | Last updated |
| --- | --- | --- |
| 2008 | 1,044 | — |
| 2010 | 6,379 | 1,005 |
| 2011–2019 | 11,880 | 3,568 |
| 2020 | 2,178 | 15,480 |
| 2021 | 1,542 | 2,968 |
| 2022+ | **0** | **0** |

The snapshot stops on **8 September 2021**. Version file `etc/rules/version.txt` is `9840`. Live updates still point at `https://rules.emergingthreats.net/open/suricata-5.0/` (and ET Pro with an oinkcode on RT6600ax). Until that updater runs, the router is detecting 2021-era malware/CVE content only.

`suricata-5.0-enhanced-open.txt` in the tarball is **empty**.

---

## 8. License (from ET `LICENSE`)

- SID 1–3464 and 100000000–100000908: GPLv2 (this pack’s GPL survivors are ET-GPL **210xxxx**, 916 enabled).
- SID 2000000–2799999: BSD 3-clause, Copyright Emerging Threats 2003–2021.
- IP-list SIDs 2400000+: same BSD tree (Spamhaus / CINS / DShield / Tor).
- Synology SID 1: proprietary exception on top of the pack.

---

## 9. Operator takeaways

1. **Enable automatic signature update** after install. The SPK copy is four–five years behind the review date.
2. **Stock “drop high-risk” does not drop C2, phishing, exploit kits, or Spamhaus/Tor lists.** Add class policies for `command-and-control`, `domain-c2`, `credential-theft`, `exploit-kit`, and `misc-attack` if you want those blocked.
3. **Phishing (1,806) and PUP (555) are almost all alert-only.** Use Self-Defined Policy or SIEM if you care about them.
4. **Do not treat `drop.rules` as a blocklist** on this product without a policy change.
5. The Google Voice pass is a single hardcoded IP; if Google moves STUN, Voice breaks or the exception is useless.

Full SID-level inventory: [`alerts-active.csv`](rules/alerts-active.csv).
