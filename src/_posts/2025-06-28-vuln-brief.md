---
title: Morning Vulnerability Briefing - 2025-06-28
date: 2025-06-28T16:17:57.446307
layout: post
tags: [vulnerability, briefing, security]
vulnerabilityCount: 29
criticalCount: 0
highCount: 0
---

# Morning Vulnerability Briefing - 2025-06-28

Today's briefing covers **29 vulnerabilities** from 0 sources.

## Risk Distribution

- 🔴 **Critical Risk**: 0 vulnerabilities
- 🟠 **High Risk**: 0 vulnerabilities
- 🟡 **Medium Risk**: 11 vulnerabilities
- 🟢 **Low Risk**: 18 vulnerabilities

## Top Vulnerabilities

### 1. [CVE-2025-21091](/api/vulns/CVE-2025-21091.json)

**Risk Score**: 44/100 | 
**Severity**: HIGH | 
**CVSS**: 7.5 | 
**EPSS**: 0.1%

**Summary**: When SNMP v1 or v2c are disabled on the BIG-IP, undisclosed requests can cause an increase in memory resource utilization.

 


Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated

**Risk Factors**:

- HIGH severity
- Affects critical infrastructure: f5

**Affected Vendors**: f5

**Tags**: `CWE-401`

**References**:

- [https://my.f5.com/manage/s/article/K000140933](https://my.f5.com/manage/s/article/K000140933)

---

### 2. [CVE-2025-21087](/api/vulns/CVE-2025-21087.json)

**Risk Score**: 44/100 | 
**Severity**: HIGH | 
**CVSS**: 7.5 | 
**EPSS**: 0.1%

**Summary**: When Client or Server SSL profiles are configured on a Virtual Server, or DNSSEC signing operations are in use, undisclosed traffic can cause an increase in memory and CPU resource utilization.

 


Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated

**Risk Factors**:

- HIGH severity
- Affects critical infrastructure: f5

**Affected Vendors**: f5

**Tags**: `CWE-400`

**References**:

- [https://my.f5.com/manage/s/article/K000134888](https://my.f5.com/manage/s/article/K000134888)

---

### 3. [CVE-2025-20003](/api/vulns/CVE-2025-20003.json)

**Risk Score**: 43/100 | 
**Severity**: HIGH | 
**CVSS**: 8.2 | 
**EPSS**: 0.0%

**Summary**: Improper link resolution before file access ('Link Following') for some Intel(R) Graphics Driver software installers may allow an authenticated user to potentially enable escalation of privilege via local access.

**Risk Factors**:

- HIGH severity

**Affected Vendors**: n/a

**Tags**: `CWE-59`

**References**:

- [https://intel.com/content/www/us/en/security-center/advisory/intel-sa-01259.html](https://intel.com/content/www/us/en/security-center/advisory/intel-sa-01259.html)

---

### 4. [CVE-2025-20008](/api/vulns/CVE-2025-20008.json)

**Risk Score**: 42/100 | 
**Severity**: HIGH | 
**CVSS**: 7.7 | 
**EPSS**: 0.0%

**Summary**: Insecure inherited permissions for some Intel(R) Simics(R) Package Manager software before version 1.12.0 may allow a privileged user to potentially enable escalation of privilege via local access.

**Risk Factors**:

- HIGH severity

**Affected Vendors**: n/a

**Tags**: `CWE-277`

**References**:

- [https://intel.com/content/www/us/en/security-center/advisory/intel-sa-01297.html](https://intel.com/content/www/us/en/security-center/advisory/intel-sa-01297.html)

---

### 5. [CVE-2025-1000](/api/vulns/CVE-2025-1000.json)

**Risk Score**: 41/100 | 
**Severity**: MEDIUM | 
**CVSS**: 5.3 | 
**EPSS**: 0.1%

**Summary**: IBM Db2 for Linux, UNIX and Windows (includes DB2 Connect Server) 11.5.0 through 11.5.9 and 12.1.0 through 12.1.1 

could allow an authenticated user to cause a denial of service when connecting to a z/OS database due to improper handling of automatic client rerouting.

**Risk Factors**:

- Affects critical infrastructure: ibm

**Affected Vendors**: ibm

**Tags**: `CWE-770`

**References**:

- [https://www.ibm.com/support/pages/node/7232528](https://www.ibm.com/support/pages/node/7232528)

---

### 6. [CVE-2025-20001](/api/vulns/CVE-2025-20001.json)

**Risk Score**: 41/100 | 
**Severity**: MEDIUM | 
**CVSS**: 6.5 | 
**EPSS**: 0.0%

**Summary**: An out-of-bounds read vulnerability exists in High-Logic FontCreator 15.0.0.3015. A specially crafted font file can trigger this vulnerability which can lead to disclosure of sensitive information. An attacker needs to trick the user into opening the malicious file to trigger this vulnerability.

**Risk Factors**:

- Published within last month

**Affected Vendors**: high-logic

**Tags**: `CWE-125`

**References**:

- [https://talosintelligence.com/vulnerability_reports/TALOS-2025-2157](https://talosintelligence.com/vulnerability_reports/TALOS-2025-2157)

---

### 7. [CVE-2025-0037](/api/vulns/CVE-2025-0037.json)

**Risk Score**: 41/100 | 
**Severity**: MEDIUM | 
**CVSS**: 6.6 | 
**EPSS**: 0.0%

**Summary**: In AMD Versal Adaptive SoC devices, the lack of address validation when executing PLM runtime services through the PLM firmware can allow access to isolated or protected memory spaces, resulting in the loss of integrity and confidentiality.

**Risk Factors**:

- Published within last month

**Affected Vendors**: amd

**Tags**: `CWE-20`

**References**:

- [https://www.amd.com/en/resources/product-security/bulletin/amd-sb-8010.html](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-8010.html)

---

### 8. [CVE-2025-20006](/api/vulns/CVE-2025-20006.json)

**Risk Score**: 41/100 | 
**Severity**: HIGH | 
**CVSS**: 7.4 | 
**EPSS**: 0.0%

**Summary**: Use after free for some Intel(R) PROSet/Wireless WiFi Software for Windows before version 23.100 may allow an unauthenticated user to potentially enable denial of service via adjacent access.

**Risk Factors**:

- HIGH severity

**Affected Vendors**: n/a

**Tags**: `CWE-416`

**References**:

- [https://intel.com/content/www/us/en/security-center/advisory/intel-sa-01270.html](https://intel.com/content/www/us/en/security-center/advisory/intel-sa-01270.html)

---

### 9. [CVE-2025-0035](/api/vulns/CVE-2025-0035.json)

**Risk Score**: 41/100 | 
**Severity**: HIGH | 
**CVSS**: 7.3 | 
**EPSS**: 0.0%

**Summary**: Unquoted search path within AMD Cloud Manageability Service can allow a local attacker to escalate privileges, potentially resulting in arbitrary code execution.

**Risk Factors**:

- HIGH severity

**Affected Vendors**: amd

**Tags**: `CWE-428`

**References**:

- [https://www.amd.com/en/resources/product-security/bulletin/amd-sb-9015.html](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-9015.html)

---

### 10. [CVE-2025-0014](/api/vulns/CVE-2025-0014.json)

**Risk Score**: 41/100 | 
**Severity**: HIGH | 
**CVSS**: 7.3 | 
**EPSS**: 0.0%

**Summary**: Incorrect default permissions on the AMD Ryzen(TM) AI installation folder could allow an attacker to achieve privilege escalation, potentially resulting in arbitrary code execution.

**Risk Factors**:

- HIGH severity

**Affected Vendors**: amd

**Tags**: `CWE-276`

**References**:

- [https://www.amd.com/en/resources/product-security/bulletin/amd-sb-7037.html](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-7037.html)

---

## Data Sources

This briefing was generated from the following sources:


---

*This briefing was automatically generated. For the complete dataset, visit the [vulnerability dashboard](/).*