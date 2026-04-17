# 🎣 Phishing Campaign Analysis — Indian BFSI Sector

**Classification:** TLP:WHITE  
**Author:** Anvesh Raju Vishwaraju  
**Date:** April 2026  
**Campaign ID:** CAMP-2026-BFSI-001

---

## Executive Summary

A large-scale phishing campaign targeting customers of Indian public and private sector banks was detected in Q1 2026. The campaign impersonated HDFC Bank, SBI, ICICI Bank, and Axis Bank using typosquat domains, SMS lures, and fake KYC update portals. Over 40 malicious domains were identified, with infrastructure hosted on bulletproof hosting in Germany and Netherlands.

**Impact:** Estimated 12,000+ credential harvest attempts across 4 weeks.

---

## Campaign Overview

| Attribute | Details |
|---|---|
| Campaign Name | Operation FakeKYC |
| Start Date | February 14, 2026 |
| Detection Date | March 2, 2026 |
| Active Duration | ~4 weeks |
| Primary Vector | SMS Phishing (Smishing) + Email |
| Targeted Banks | HDFC, SBI, ICICI, Axis, Kotak |
| Infrastructure | Bulletproof hosting (DE, NL) |
| Threat Actor | Unattributed — financially motivated |
| MITRE Tactics | Initial Access, Credential Access |

---

## Attack Chain

```
Step 1: SMS sent to victim
        "Your KYC is expiring. Update now or account blocked:
         http://hdfc-kyc-update[.]in"
         
Step 2: Victim clicks link → Redirect chain
        hdfc-kyc-update[.]in
        → 185.220.101.47 (proxy)
        → fake-hdfc-portal[.]com (phishing kit)
        
Step 3: Victim enters credentials on fake portal
        (looks identical to real HDFC NetBanking)
        
Step 4: Credentials POSTed to attacker C2
        POST /collect.php
        {username, password, mobile, otp}
        
Step 5: Victim redirected to real HDFC site
        (appears like successful login)
        
Step 6: Attacker uses stolen creds for:
        - Fraudulent UPI transfers
        - Account takeover
        - PII harvesting for further fraud
```

---

## Infrastructure Analysis

### Domains (40 identified)

| Domain | Impersonating | Registrar | IP | Status |
|---|---|---|---|---|
| hdfc-kyc-update[.]in | HDFC Bank | Namecheap | 185.220.101.47 | 🔴 Active |
| sbi-account-verify[.]com | SBI | GoDaddy | 45.142.212.100 | 🔴 Active |
| icici-secure-login[.]net | ICICI | PDR Ltd | 185.220.101.48 | 🟡 Inactive |
| axis-netbanking-kyc[.]com | Axis Bank | Namecheap | 45.142.212.101 | 🔴 Active |
| kotak-update-kyc[.]in | Kotak | GoDaddy | 185.220.101.49 | 🔴 Active |

**Pattern observed:** All domains registered within 3 days of campaign start. Privacy protection enabled on all.

### Hosting Infrastructure

```
AS60729 (Liteserver B.V., Netherlands) — Primary
  185.220.101.47 — Reverse proxy / redirector
  185.220.101.48 — Phishing kit host
  185.220.101.49 — C2 / credential collector

AS20473 (Vultr, Germany) — Secondary
  45.142.212.100 — Backup phishing host
  45.142.212.101 — Backup redirector
```

### Phishing Kit Analysis

- **Kit name:** "BankPhish v3.2" (watermark found in obfuscated JS)
- **Capabilities:** Real-time OTP relay, credential logging, geo-IP filtering
- **Evasion:** Blocks VPN IPs, shows blank page to security researchers
- **Language:** PHP backend, JavaScript frontend

---

## IOCs

### IP Addresses
```
185.220.101.47   # Primary redirector
185.220.101.48   # Phishing kit host
185.220.101.49   # Credential collector C2
45.142.212.100   # Backup host
45.142.212.101   # Backup redirector
```

### Domains
```
hdfc-kyc-update[.]in
sbi-account-verify[.]com
icici-secure-login[.]net
axis-netbanking-kyc[.]com
kotak-update-kyc[.]in
secure-hdfc-netbanking[.]com
[+35 more — full list in ioc-enrichment/]
```

### URLs
```
hxxp://hdfc-kyc-update[.]in/kyc/verify
hxxp://sbi-account-verify[.]com/login
hxxp://[ip]/collect.php  (credential harvester)
```

### Email Subjects Observed
```
"URGENT: Your HDFC Bank KYC expires in 24 hours"
"SBI Account Suspended — Verify Now"
"ICICI Bank Security Alert — Action Required"
```

---

## MITRE ATT&CK Mapping

| Phase | Technique | ID |
|---|---|---|
| Initial Access | Spearphishing Link (SMS) | T1566.002 |
| Credential Access | Steal Web Session Cookie | T1539 |
| Credential Access | Input Capture: Web Portal | T1056.003 |
| Collection | Data from Information Repositories | T1213 |
| Exfiltration | Exfiltration Over Web Service | T1567 |

---

## Recommendations

### Immediate (Block Today)
- Block all 40 IOC domains and 5 IPs at DNS gateway and firewall
- Alert customers via SMS/email warning about the campaign
- Submit IOCs to CERT-In for national-level blocking

### Short-Term (30 days)
- Implement DMARC enforcement to prevent email spoofing
- Monitor for new typosquat domains using brand monitoring tools
- Conduct targeted phishing simulation for banking customers

### Long-Term
- Deploy real-time phishing URL detection on mobile banking app
- Integrate threat intel feed for auto-blocking of new phishing domains
- Join BFSI-ISAC for shared threat intelligence

---

*Report by: Anvesh Raju Vishwaraju | anvesh65422@gmail.com | +91 79812 93129*
