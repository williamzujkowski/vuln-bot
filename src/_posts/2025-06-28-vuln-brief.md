---
title: Morning Vulnerability Briefing - 2025-06-28
date: 2025-06-28T16:30:34.192494
layout: layouts/post.njk
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

### 11. [CVE-2025-20004](/api/vulns/CVE-2025-20004.json)

**Risk Score**: 40/100 | 
**Severity**: HIGH | 
**CVSS**: 7.2 | 
**EPSS**: 0.0%

**Summary**: Insufficient control flow management in the Alias Checking Trusted Module for some Intel(R) Xeon(R) 6 processor E-Cores firmware may allow a privileged user to potentially enable escalation of privilege via local access.

**Risk Factors**:

- HIGH severity

**Affected Vendors**: n/a

**Tags**: `CWE-691`

**References**:

- [https://intel.com/content/www/us/en/security-center/advisory/intel-sa-01273.html](https://intel.com/content/www/us/en/security-center/advisory/intel-sa-01273.html)

---

### 12. [CVE-2025-1005](/api/vulns/CVE-2025-1005.json)

**Risk Score**: 39/100 | 
**Severity**: MEDIUM | 
**CVSS**: 6.4 | 
**EPSS**: 0.1%

**Summary**: The ElementsKit Elementor addons plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the plugin's Image Accordion widget in all versions up to, and including, 3.4.0 due to insufficient input sanitization and output escaping on user supplied attributes. This makes it possible for authenticated attackers, with contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

**Affected Vendors**: xpeedstudio

**Tags**: `CWE-79`

**References**:

- [https://www.wordfence.com/threat-intel/vulnerabilities/id/5b74d6aa-ad59-42be-b454-9c27428cab01?source=cve](https://www.wordfence.com/threat-intel/vulnerabilities/id/5b74d6aa-ad59-42be-b454-9c27428cab01?source=cve)
- [https://plugins.trac.wordpress.org/browser/elementskit-lite/trunk/modules/layout-manager/assets/js/ekit-layout-library.js](https://plugins.trac.wordpress.org/browser/elementskit-lite/trunk/modules/layout-manager/assets/js/ekit-layout-library.js)
- [https://wordpress.org/plugins/elementskit-lite/#developers](https://wordpress.org/plugins/elementskit-lite/#developers)

---

### 13. [CVE-2025-1008](/api/vulns/CVE-2025-1008.json)

**Risk Score**: 38/100 | 
**Severity**: MEDIUM | 
**CVSS**: 6.4 | 
**EPSS**: 0.0%

**Summary**: The Recently Purchased Products For Woo plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the ‘view’ parameter in all versions up to, and including, 1.1.3 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

**Affected Vendors**: worldweb

**Tags**: `CWE-79`

**References**:

- [https://www.wordfence.com/threat-intel/vulnerabilities/id/c9ebcd32-90c1-419c-a67c-6fe41ee9fab1?source=cve](https://www.wordfence.com/threat-intel/vulnerabilities/id/c9ebcd32-90c1-419c-a67c-6fe41ee9fab1?source=cve)
- [https://plugins.trac.wordpress.org/browser/recently-purchased-products-for-woo/tags/1.1.3/includes/class-rppw-public.php#L160](https://plugins.trac.wordpress.org/browser/recently-purchased-products-for-woo/tags/1.1.3/includes/class-rppw-public.php#L160)
- [https://wordpress.org/plugins/recently-purchased-products-for-woo/#developers](https://wordpress.org/plugins/recently-purchased-products-for-woo/#developers)

---

### 14. [CVE-2025-21083](/api/vulns/CVE-2025-21083.json)

**Risk Score**: 37/100 | 
**Severity**: MEDIUM | 
**CVSS**: 6.5 | 
**EPSS**: 0.1%

**Summary**: Mattermost Mobile Apps versions <=2.22.0 fail to properly validate post props which allows a malicious authenticated user to cause a crash via a malicious post.

**Affected Vendors**: mattermost

**Tags**: `CWE-1287`

**References**:

- [https://mattermost.com/security-updates](https://mattermost.com/security-updates)

---

### 15. [CVE-2025-0001](/api/vulns/CVE-2025-0001.json)

**Risk Score**: 37/100 | 
**Severity**: MEDIUM | 
**CVSS**: 6.5 | 
**EPSS**: 0.1%

**Summary**: Abacus ERP is versions older than 2024.210.16036, 2023.205.15833, 2022.105.15542 are affected by an authenticated arbitrary file read vulnerability.

**Affected Vendors**: abacus research ag

**Tags**: `CWE-36`

**References**:

- [https://borelenzo.github.io/stuff/2025/02/15/CVE-2025-0001.html](https://borelenzo.github.io/stuff/2025/02/15/CVE-2025-0001.html)

---

### 16. [CVE-2025-21088](/api/vulns/CVE-2025-21088.json)

**Risk Score**: 37/100 | 
**Severity**: MEDIUM | 
**CVSS**: 6.5 | 
**EPSS**: 0.1%

**Summary**: Mattermost versions 10.2.x <= 10.2.0, 9.11.x <= 9.11.5, 10.0.x <= 10.0.3, 10.1.x <= 10.1.3 fail to properly validate the style of proto supplied to an action's style in post.props.attachments, which allows an attacker to crash the frontend via crafted malicious input.

**Affected Vendors**: mattermost

**Tags**: `CWE-704`

**References**:

- [https://mattermost.com/security-updates](https://mattermost.com/security-updates)

---

### 17. [CVE-2025-21092](/api/vulns/CVE-2025-21092.json)

**Risk Score**: 37/100 | 
**Severity**: MEDIUM | 
**CVSS**: 6.5 | 
**EPSS**: 0.0%

**Summary**: GMOD Apollo does not have sufficient logical or access checks when updating a user's information. This could result in an attacker being able to escalate privileges for themselves or others.

**Affected Vendors**: gmod

**Tags**: `CWE-266`

**References**:

- [https://www.cisa.gov/news-events/ics-advisories/icsa-25-063-07](https://www.cisa.gov/news-events/ics-advisories/icsa-25-063-07)

---

### 18. [CVE-2025-20013](/api/vulns/CVE-2025-20013.json)

**Risk Score**: 36/100 | 
**Severity**: MEDIUM | 
**CVSS**: 5.5 | 
**EPSS**: 0.0%

**Summary**: Exposure of sensitive information to an unauthorized actor for some Edge Orchestrator software for Intel(R) Tiber™ Edge Platform may allow an authenticated user to potentially enable information disclosure via local access.

**Affected Vendors**: n/a

**Tags**: `CWE-200`

**References**:

- [https://intel.com/content/www/us/en/security-center/advisory/intel-sa-01239.html](https://intel.com/content/www/us/en/security-center/advisory/intel-sa-01239.html)

---

### 19. [CVE-2025-20012](/api/vulns/CVE-2025-20012.json)

**Risk Score**: 35/100 | 
**Severity**: MEDIUM | 
**CVSS**: 4.9 | 
**EPSS**: 0.0%

**Summary**: Incorrect behavior order for some Intel(R) Core™ Ultra Processors may allow an unauthenticated user to potentially enable information disclosure via physical access.

**Affected Vendors**: n/a

**Tags**: `CWE-696`

**References**:

- [https://intel.com/content/www/us/en/security-center/advisory/intel-sa-01322.html](https://intel.com/content/www/us/en/security-center/advisory/intel-sa-01322.html)

---

### 20. [CVE-2025-1001](/api/vulns/CVE-2025-1001.json)

**Risk Score**: 35/100 | 
**Severity**: MEDIUM | 
**CVSS**: 5.7 | 
**EPSS**: 0.0%

**Summary**: Medixant RadiAnt DICOM Viewer is vulnerable due to failure of the update mechanism to verify the update server's certificate which could allow an attacker to alter network traffic and carry out a machine-in-the-middle attack (MITM). An attacker could modify the server's response and deliver a malicious update to the user.

**Affected Vendors**: medixant

**Tags**: `CWE-295`

**References**:

- [https://www.cisa.gov/news-events/ics-medical-advisories/icsma-25-051-01](https://www.cisa.gov/news-events/ics-medical-advisories/icsma-25-051-01)
- [https://www.radiantviewer.com/files/RadiAnt-2025.1-Setup.exe](https://www.radiantviewer.com/files/RadiAnt-2025.1-Setup.exe)

---

### 21. [CVE-2025-1002](/api/vulns/CVE-2025-1002.json)

**Risk Score**: 35/100 | 
**Severity**: MEDIUM | 
**CVSS**: 5.7 | 
**EPSS**: 0.0%

**Summary**: MicroDicom DICOM Viewer version 2024.03

fails to adequately verify the update server's certificate, which could make it possible for attackers in a privileged network position to alter network traffic and carry out a machine-in-the-middle (MITM) attack. This allows the attackers to modify the server's response and deliver a malicious update to the user.

**Affected Vendors**: microdicom

**Tags**: `CWE-295`

**References**:

- [https://www.cisa.gov/news-events/ics-medical-advisories/icsma-25-037-01](https://www.cisa.gov/news-events/ics-medical-advisories/icsma-25-037-01)

---

### 22. [CVE-2025-20002](/api/vulns/CVE-2025-20002.json)

**Risk Score**: 34/100 | 
**Severity**: MEDIUM | 
**CVSS**: 5.3 | 
**EPSS**: 0.0%

**Summary**: After attempting to upload a file that does not meet prerequisites, GMOD Apollo will respond with local path information disclosure

**Affected Vendors**: gmod

**Tags**: `CWE-209`

**References**:

- [https://www.cisa.gov/news-events/ics-advisories/icsa-25-063-07](https://www.cisa.gov/news-events/ics-advisories/icsa-25-063-07)
- [https://github.com/GMOD/Apollo](https://github.com/GMOD/Apollo)

---

### 23. [CVE-2025-21081](/api/vulns/CVE-2025-21081.json)

**Risk Score**: 34/100 | 
**Severity**: MEDIUM | 
**CVSS**: 4.5 | 
**EPSS**: 0.0%

**Summary**: Protection mechanism failure for some Edge Orchestrator software for Intel(R) Tiber™ Edge Platform may allow an authenticated user to potentially enable escalation of privilege via local access.

**Affected Vendors**: n/a

**Tags**: `CWE-693`

**References**:

- [https://intel.com/content/www/us/en/security-center/advisory/intel-sa-01239.html](https://intel.com/content/www/us/en/security-center/advisory/intel-sa-01239.html)

---

### 24. [CVE-2025-20009](/api/vulns/CVE-2025-20009.json)

**Risk Score**: 33/100 | 
**Severity**: MEDIUM | 
**CVSS**: 4.1 | 
**EPSS**: 0.0%

**Summary**: Improper input validation in the UEFI firmware GenerationSetup module for the Intel(R) Server D50DNP and M50FCP boards may allow a privileged user to potentially enable information disclosure via local access.

**Affected Vendors**: n/a

**Tags**: `CWE-20`

**References**:

- [https://intel.com/content/www/us/en/security-center/advisory/intel-sa-01269.html](https://intel.com/content/www/us/en/security-center/advisory/intel-sa-01269.html)

---

### 25. [CVE-2025-1006](/api/vulns/CVE-2025-1006.json)

**Risk Score**: 26/100 | 
**Severity**: NONE | 
**CVSS**: N/A | 
**EPSS**: 0.2%

**Summary**: Use after free in Network in Google Chrome prior to 133.0.6943.126 allowed a remote attacker to potentially exploit heap corruption via a crafted web app. (Chromium security severity: Medium)

**Risk Factors**:

- Affects critical infrastructure: google

**Affected Vendors**: google

**References**:

- [https://chromereleases.googleblog.com/2025/02/stable-channel-update-for-desktop_18.html](https://chromereleases.googleblog.com/2025/02/stable-channel-update-for-desktop_18.html)
- [https://issues.chromium.org/issues/390590778](https://issues.chromium.org/issues/390590778)

---

### 26. [CVE-2025-22004](/api/vulns/CVE-2025-22004.json)

**Risk Score**: 26/100 | 
**Severity**: NONE | 
**CVSS**: N/A | 
**EPSS**: 0.0%

**Summary**: In the Linux kernel, the following vulnerability has been resolved:

net: atm: fix use after free in lec_send()

The ->send() operation frees skb so save the length before calling
->send() to avoid a use after free.

**Affected Vendors**: linux

**References**:

- [https://git.kernel.org/stable/c/50e288097c2c6e5f374ae079394436fc29d1e88e](https://git.kernel.org/stable/c/50e288097c2c6e5f374ae079394436fc29d1e88e)
- [https://git.kernel.org/stable/c/8cd90c7db08f32829bfa1b5b2b11fbc542afbab7](https://git.kernel.org/stable/c/8cd90c7db08f32829bfa1b5b2b11fbc542afbab7)
- [https://git.kernel.org/stable/c/82d9084a97892de1ee4881eb5c17911fcd9be6f6](https://git.kernel.org/stable/c/82d9084a97892de1ee4881eb5c17911fcd9be6f6)

---

### 27. [CVE-2025-1009](/api/vulns/CVE-2025-1009.json)

**Risk Score**: 24/100 | 
**Severity**: NONE | 
**CVSS**: N/A | 
**EPSS**: 0.2%

**Summary**: An attacker could have caused a use-after-free via crafted XSLT data, leading to a potentially exploitable crash. This vulnerability affects Firefox < 135, Firefox ESR < 115.20, Firefox ESR < 128.7, Thunderbird < 128.7, and Thunderbird < 135.

**Affected Vendors**: mozilla

**References**:

- [https://bugzilla.mozilla.org/show_bug.cgi?id=1936613](https://bugzilla.mozilla.org/show_bug.cgi?id=1936613)
- [https://www.mozilla.org/security/advisories/mfsa2025-07/](https://www.mozilla.org/security/advisories/mfsa2025-07/)
- [https://www.mozilla.org/security/advisories/mfsa2025-08/](https://www.mozilla.org/security/advisories/mfsa2025-08/)

---

### 28. [CVE-2025-0050](/api/vulns/CVE-2025-0050.json)

**Risk Score**: 22/100 | 
**Severity**: NONE | 
**CVSS**: N/A | 
**EPSS**: 0.0%

**Summary**: Improper Restriction of Operations within the Bounds of a Memory Buffer vulnerability in Arm Ltd Bifrost GPU Userspace Driver, Arm Ltd Valhall GPU Userspace Driver, Arm Ltd Arm 5th Gen GPU Architecture Userspace Driver allows a non-privileged user process to make valid GPU processing operations, including via WebGL or WebGPU, to access a limited amount outside of buffer bounds.This issue affects Bifrost GPU Userspace Driver: from r0p0 through r49p2, from r50p0 through r51p0; Valhall GPU Userspac...

**Affected Vendors**: arm ltd

**Tags**: `CWE-119`

**References**:

- [https://developer.arm.com/documentation/110435/latest/](https://developer.arm.com/documentation/110435/latest/)

---

### 29. [CVE-2025-0015](/api/vulns/CVE-2025-0015.json)

**Risk Score**: 20/100 | 
**Severity**: NONE | 
**CVSS**: N/A | 
**EPSS**: 0.0%

**Summary**: Use After Free vulnerability in Arm Ltd Valhall GPU Kernel Driver, Arm Ltd Arm 5th Gen GPU Architecture Kernel Driver allows a local non-privileged user process to make improper GPU processing operations to gain access to already freed memory.This issue affects Valhall GPU Kernel Driver: from r48p0 through r49p1, from r50p0 through r52p0; Arm 5th Gen GPU Architecture Kernel Driver: from r48p0 through r49p1, from r50p0 through r52p0.

**Affected Vendors**: arm ltd

**Tags**: `CWE-416`

**References**:

- [https://developer.arm.com/Arm%20Security%20Center/Mali%20GPU%20Driver%20Vulnerabilities](https://developer.arm.com/Arm%20Security%20Center/Mali%20GPU%20Driver%20Vulnerabilities)

---

## Data Sources

This briefing was generated from the following sources:


---

*This briefing was automatically generated. For the complete dataset, visit the [vulnerability dashboard](/).*