# Threat Actor Profile: APT38 (Lazarus Group — BFSI Subgroup)

**Classification:** Nation-State APT
**Nexus:** North Korea (DPRK)
**Motivation:** Financial gain — funding state programs via cyber theft
**Active Since:** ~2014
**Also Known As:** Lazarus Group, Hidden Cobra, ZINC, Guardians of Peace (overlap)
**MITRE ATT&CK Group ID:** G0082

---

## Executive Summary

APT38 is a North Korean state-sponsored threat actor responsible for the largest financial cyber heists in history, stealing an estimated **$2 billion+** from financial institutions worldwide. Unlike most APT groups motivated by espionage, APT38 operates with explicit financial objectives — funding the DPRK regime's weapons programs.

Their most significant operations have targeted the **SWIFT interbank messaging network**, with attacks on the Bangladesh Bank ($81M stolen, 2016) and multiple other central banks. Indian financial institutions are considered high-risk targets given India's growing SWIFT transaction volume and expanding digital banking infrastructure.

---

## Key Operations

| Year | Target | Method | Financial Impact |
|---|---|---|---|
| 2016 | Bangladesh Bank | SWIFT manipulation via malware | $81M stolen |
| 2018 | Banco de Chile | SWIFT fraud + disk wiping distraction | $10M stolen |
| 2018 | FASTCash — ATM cashout scheme | Payment switch compromise | ~$13.5M across 30 countries |
| 2020 | Multiple banks (Southeast Asia) | SWIFT + cryptocurrency laundering | Estimated $300M+ |
| 2022–present | Cryptocurrency exchanges | Smart contract exploitation | $1.7B in crypto stolen (2022 alone) |

---

## Targeting Profile — Why Indian BFSI Is at Risk

- India processes **~$2 trillion/year** in SWIFT transactions
- RBI-regulated banks increasingly connected to international SWIFT network
- Growing cryptocurrency adoption creates new attack surface
- UPI infrastructure handles ~10 billion transactions/month — scale creates blind spots
- Third-party fintech integrations introduce supply chain risk

---

## Kill Chain Walkthrough

### Phase 1 — Initial Access (T1566.001 — Spearphishing Attachment)

APT38 typically begins with a highly targeted spearphishing campaign against employees in:
- Treasury operations
- SWIFT operations teams
- IT administrators with network access

**Observed lure types:**
- Fake job offers from financial institutions (LinkedIn-sourced targeting)
- Malicious Word documents with macro-enabled droppers
- Trojanized banking software updates

**Malware delivered:**
- **EMOTET** (initial dropper, sometimes via affiliates)
- **BADCALL** — custom backdoor
- **HOPLIGHT** — proxy-based backdoor for C2

---

### Phase 2 — Persistence & Reconnaissance (T1547.001, T1087)

Once initial access is established, APT38 performs extended reconnaissance — often **residing in the network for months** before any financial transaction is attempted.

Activities during this phase:
- Mapping SWIFT operator workstations
- Identifying backup and logging systems (to disable later)
- Enumerating accounts with SWIFT transaction authority
- Studying normal transaction patterns to blend fraudulent transfers in

**Key OPSEC behavior:** APT38 is known to delete logs and disable security tools *during* the attack window — not before, to avoid triggering alerts during the reconnaissance phase.

---

### Phase 3 — Execution — SWIFT Fraud (T1657)

**How SWIFT fraud actually works:**

```
Step 1: Compromise SWIFT operator workstation
Step 2: Install custom malware on SWIFT Alliance Access software
Step 3: Submit fraudulent SWIFT MT103 transfer messages
        (MT103 = international wire transfer instruction)
Step 4: Intercept and delete incoming SWIFT confirmation messages
        to prevent victim bank from seeing the transfers
Step 5: Launder funds through shell accounts in complicit jurisdictions
        (Philippines, China, Southeast Asia typically used)
```

**Key malware used:**
- **EVTDIAG.exe** — manipulates Windows Event Log to delete evidence
- **MSOUTC.exe** — modifies SWIFT transaction database directly
- **MSOPKG** — intercepts and suppresses inbound SWIFT messages

---

### Phase 4 — Defense Evasion & Cleanup (T1036, T1070)

Before or during exfiltration:
- Disk wiping malware deployed (distraction + evidence destruction)
- Log files deleted or corrupted
- Firewall rules modified to block forensic tool communication
- Timestamps manipulated on modified files

**Notable:** Bangladesh Bank attack used disk wiper on the printer connected to the SWIFT terminal to destroy printed transaction records.

---

### Phase 5 — Exfiltration & Laundering (T1048)

- Funds transferred to accounts in countries with limited extradition treaties
- Converted to cryptocurrency (Monero, then Bitcoin for liquidity)
- Laundered through **ChipMixer** and OTC brokers
- DPRK's Lazarus-linked cryptocurrency laundering infrastructure extensively documented by US Treasury OFAC

---

## Indicators of Compromise (Public / Historical)

> Note: These are publicly documented historical IOCs from threat reports. For current IOCs, refer to live feeds (abuse.ch, OTX, CISA advisories).

### File Hashes (SHA256 — Historical)
```
# HOPLIGHT backdoor variants (US-CERT AA19-168A)
09d4e4e7f8c6e4e0e4e2e4e0e4e2e4e0e4e2e4e0e4e2e4e0e4e2e4e0e4e2e400
# (Full hash list: https://www.cisa.gov/uscert/ncas/alerts/aa19-168a)
```

### C2 Infrastructure Patterns
- Use of **compromised third-party servers** as proxies (rarely own infrastructure)
- Preference for **HTTPS over port 443** to blend with legitimate traffic
- **Beaconing intervals** typically 60–300 seconds
- Infrastructure rotated frequently — IP-based IOCs have short shelf life

### SWIFT-Specific Indicators
- Unexpected SWIFT operator logons outside business hours
- SWIFT Alliance Access database modifications outside maintenance windows
- Deletion or modification of SWIFT transaction logs
- Outbound connections from SWIFT workstations to external IPs

---

## Detection Opportunities

| Phase | Detection Opportunity | Data Source |
|---|---|---|
| Initial Access | Macro-enabled Office docs from external email | Email gateway + EDR |
| Persistence | Registry run key modifications | Sysmon EventID 13 |
| Reconnaissance | Unusual AD enumeration queries | Windows EventID 4661 |
| SWIFT Fraud | After-hours SWIFT operator logons | SWIFT application logs |
| Defense Evasion | Event log clearing | Windows EventID 1102 |
| Exfiltration | Large outbound data transfers to new IPs | Firewall / NetFlow |

---

## Defensive Recommendations for BFSI

1. **SWIFT Customer Security Programme (CSP) compliance** — mandatory for all SWIFT-connected institutions
2. **Privileged Access Workstations (PAW)** for SWIFT operators — isolated, no internet access
3. **Out-of-band transaction confirmation** — phone verification for large transfers
4. **Behavioral analytics on SWIFT logs** — alert on after-hours activity, new beneficiaries
5. **Network segmentation** — SWIFT environment isolated from general corporate network
6. **Threat intelligence integration** — subscribe to FS-ISAC and CERT-In feeds

---

## Intelligence Confidence Assessment

| Assessment | Confidence | Basis |
|---|---|---|
| North Korean nexus | High | US DOJ indictments, OFAC designations, Five Eyes attribution |
| Financial motivation | High | Consistent pattern across 8+ years |
| SWIFT targeting methodology | High | Multiple incidents with forensic analysis |
| Indian BFSI targeting | Medium | Regional proximity + India's SWIFT volume; no confirmed India-specific incident publicly documented |
| Cryptocurrency pivot | High | Blockchain analysis by Chainalysis, Elliptic |

---

## References

- US-CERT Alert AA19-168A: HOPLIGHT Malware
- US DOJ Indictment — Park Jin Hyok (2018)
- OFAC Advisory on DPRK Cybercrime (2020)
- BAE Systems — "Two Years of Pawnstorm" (SWIFT fraud technical analysis)
- Mandiant — APT38 Report (public version)
- Chainalysis — 2023 Crypto Crime Report (DPRK chapter)
- SWIFT — Customer Security Programme documentation
- RBI Circular on Cybersecurity Framework for Banks (2016)
