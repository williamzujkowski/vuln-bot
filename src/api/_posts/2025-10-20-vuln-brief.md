---
title: Morning Vulnerability Briefing - 2025-10-20
date: 2025-10-20T02:35:01.596827
layout: layouts/post.njk
tags: [vulnerability, briefing, security]
vulnerabilityCount: 295
criticalCount: 0
highCount: 104
---

# Morning Vulnerability Briefing - 2025-10-20

Today's briefing covers **295 vulnerabilities** from 0 sources.

## Risk Distribution

- 🔴 **Critical Risk**: 0 vulnerabilities
- 🟠 **High Risk**: 104 vulnerabilities
- 🟡 **Medium Risk**: 173 vulnerabilities
- 🟢 **Low Risk**: 18 vulnerabilities

## Top Vulnerabilities

### 1. [CVE-2024-27198](/api/vulns/CVE-2024-27198.json)

**Risk Score**: 88/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 94.6%

**Summary**: In JetBrains TeamCity before 2023.11.4 authentication bypass allowing to perform admin actions was possible

**Risk Factors**:

- CRITICAL severity
- 94.58% exploit probability

**Affected Vendors**: Jetbrains

**References**:

- [https://www.jetbrains.com/privacy-security/issues-fixed/](https://www.jetbrains.com/privacy-security/issues-fixed/)
- [https://www.darkreading.com/cyberattacks-data-breaches/jetbrains-teamcity-mass-exploitation-underway-rogue-accounts-thrive](https://www.darkreading.com/cyberattacks-data-breaches/jetbrains-teamcity-mass-exploitation-underway-rogue-accounts-thrive)

---

### 2. [CVE-2024-7593](/api/vulns/CVE-2024-7593.json)

**Risk Score**: 88/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 94.4%

**Summary**: Incorrect implementation of an authentication algorithm in Ivanti vTM other than versions 22.2R1 or 22.7R2 allows a remote unauthenticated attacker to bypass authentication of the admin panel.

**Risk Factors**:

- CRITICAL severity
- 94.44% exploit probability

**Affected Vendors**: Ivanti

**Tags**: `CWE-287`, `CWE-303`

**References**:

- [https://forums.ivanti.com/s/article/Security-Advisory-Ivanti-Virtual-Traffic-Manager-vTM-CVE-2024-7593](https://forums.ivanti.com/s/article/Security-Advisory-Ivanti-Virtual-Traffic-Manager-vTM-CVE-2024-7593)

---

### 3. [CVE-2024-4040](/api/vulns/CVE-2024-4040.json)

**Risk Score**: 88/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 94.4%

**Summary**: A server side template injection vulnerability in CrushFTP in all versions before 10.7.1 and 11.1.0 on all platforms allows unauthenticated remote attackers to read files from the filesystem outside of the VFS Sandbox, bypass authentication to gain administrative access, and perform remote code execution on the server.


**Risk Factors**:

- CRITICAL severity
- 94.43% exploit probability

**Affected Vendors**: Crushftp, The

**Tags**: `CWE-1336`

**References**:

- [https://www.crushftp.com/crush11wiki/Wiki.jsp?page=Update](https://www.crushftp.com/crush11wiki/Wiki.jsp?page=Update)
- [https://www.crushftp.com/crush10wiki/Wiki.jsp?page=Update](https://www.crushftp.com/crush10wiki/Wiki.jsp?page=Update)
- [https://www.reddit.com/r/cybersecurity/comments/1c850i2/all_versions_of_crush_ftp_are_vulnerable/](https://www.reddit.com/r/cybersecurity/comments/1c850i2/all_versions_of_crush_ftp_are_vulnerable/)

---

### 4. [CVE-2024-36401](/api/vulns/CVE-2024-36401.json)

**Risk Score**: 88/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 94.4%

**Summary**: GeoServer is an open source server that allows users to share and edit geospatial data. Prior to versions 2.22.6, 2.23.6, 2.24.4, and 2.25.2, multiple OGC request parameters allow Remote Code Execution (RCE) by unauthenticated users through specially crafted input against a default GeoServer installation due to unsafely evaluating property names as XPath expressions.

The GeoTools library API that GeoServer calls evaluates property/attribute names for feature types in a way that unsafely passes ...

**Risk Factors**:

- CRITICAL severity
- 94.43% exploit probability

**Affected Vendors**: Geoserver, Source

**Tags**: `CWE-95`

**References**:

- [https://github.com/geoserver/geoserver/security/advisories/GHSA-6jj6-gm7p-fcvv](https://github.com/geoserver/geoserver/security/advisories/GHSA-6jj6-gm7p-fcvv)
- [https://github.com/geotools/geotools/security/advisories/GHSA-w3pj-wh35-fq8w](https://github.com/geotools/geotools/security/advisories/GHSA-w3pj-wh35-fq8w)
- [https://github.com/geotools/geotools/pull/4797](https://github.com/geotools/geotools/pull/4797)

---

### 5. [CVE-2024-4577](/api/vulns/CVE-2024-4577.json)

**Risk Score**: 88/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 94.4%

**Summary**: In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

**Risk Factors**:

- CRITICAL severity
- 94.37% exploit probability

**Affected Vendors**: PHP, Php Group, The

**Tags**: `CWE-78`

**References**:

- [https://github.com/php/php-src/security/advisories/GHSA-3qgc-jrrr-25jv](https://github.com/php/php-src/security/advisories/GHSA-3qgc-jrrr-25jv)
- [https://blog.orange.tw/2024/06/cve-2024-4577-yet-another-php-rce.html](https://blog.orange.tw/2024/06/cve-2024-4577-yet-another-php-rce.html)
- [https://devco.re/blog/2024/06/06/security-alert-cve-2024-4577-php-cgi-argument-injection-vulnerability-en/](https://devco.re/blog/2024/06/06/security-alert-cve-2024-4577-php-cgi-argument-injection-vulnerability-en/)

---

### 6. [CVE-2024-8963](/api/vulns/CVE-2024-8963.json)

**Risk Score**: 88/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.4 | 
**EPSS**: 94.4%

**Summary**: Path Traversal in the Ivanti CSA before 4.6 Patch 519 allows a remote unauthenticated attacker to access restricted functionality.

**Risk Factors**:

- CRITICAL severity
- 94.37% exploit probability

**Affected Vendors**: Ivanti

**Tags**: `CWE-22`

**References**:

- [https://forums.ivanti.com/s/article/Security-Advisory-Ivanti-CSA-4-6-Cloud-Services-Appliance-CVE-2024-8963](https://forums.ivanti.com/s/article/Security-Advisory-Ivanti-CSA-4-6-Cloud-Services-Appliance-CVE-2024-8963)

---

### 7. [CVE-2024-1212](/api/vulns/CVE-2024-1212.json)

**Risk Score**: 88/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 94.4%

**Summary**: Unauthenticated remote attackers can access the system through the LoadMaster management interface, enabling arbitrary system command execution.




**Risk Factors**:

- CRITICAL severity
- 94.36% exploit probability

**Affected Vendors**: Progress Software

**Tags**: `CWE-78`

**References**:

- [https://kemptechnologies.com/](https://kemptechnologies.com/)
- [https://freeloadbalancer.com/](https://freeloadbalancer.com/)
- [https://support.kemptechnologies.com/hc/en-us/articles/24325072850573-Release-Notice-LMOS-7-2-59-2-7-2-54-8-7-2-48-10-CVE-2024-1212](https://support.kemptechnologies.com/hc/en-us/articles/24325072850573-Release-Notice-LMOS-7-2-59-2-7-2-54-8-7-2-48-10-CVE-2024-1212)

---

### 8. [CVE-2024-4879](/api/vulns/CVE-2024-4879.json)

**Risk Score**: 88/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 94.3%

**Summary**: ServiceNow has addressed an input validation vulnerability that was identified in Vancouver and Washington DC Now Platform releases. This vulnerability could enable an unauthenticated user to remotely execute code within the context of the Now Platform. ServiceNow applied an update to hosted instances, and ServiceNow released the update to our partners and self-hosted customers. Listed below are the patches and hot fixes that address the vulnerability. If you have not done so already, we recomme...

**Risk Factors**:

- CRITICAL severity
- 94.35% exploit probability

**Affected Vendors**: Servicenow

**Tags**: `CWE-1287`

**References**:

- [https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB1645154](https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB1645154)
- [https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB1644293](https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB1644293)
- [https://www.darkreading.com/cloud-security/patchnow-servicenow-critical-rce-bugs-active-exploit](https://www.darkreading.com/cloud-security/patchnow-servicenow-critical-rce-bugs-active-exploit)

---

### 9. [CVE-2024-50603](/api/vulns/CVE-2024-50603.json)

**Risk Score**: 88/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 94.3%

**Summary**: An issue was discovered in Aviatrix Controller before 7.1.4191 and 7.2.x before 7.2.4996. Due to the improper neutralization of special elements used in an OS command, an unauthenticated attacker is able to execute arbitrary code. Shell metacharacters can be sent to /v1/api in cloud_type for list_flightpath_destination_instances, or src_cloud_type for flightpath_connection_test.

**Risk Factors**:

- CRITICAL severity
- 94.35% exploit probability

**Affected Vendors**: Aviatrix

**Tags**: `CWE-78`

**References**:

- [https://docs.aviatrix.com/documentation/latest/network-security/index.html](https://docs.aviatrix.com/documentation/latest/network-security/index.html)
- [https://docs.aviatrix.com/documentation/latest/release-notices/psirt-advisories/psirt-advisories.html?expand=true#remote-code-execution-vulnerability-in-aviatrix-controllers](https://docs.aviatrix.com/documentation/latest/release-notices/psirt-advisories/psirt-advisories.html?expand=true#remote-code-execution-vulnerability-in-aviatrix-controllers)
- [https://www.securing.pl/en/cve-2024-50603-aviatrix-network-controller-command-injection-vulnerability/](https://www.securing.pl/en/cve-2024-50603-aviatrix-network-controller-command-injection-vulnerability/)

---

### 10. [CVE-2024-4358](/api/vulns/CVE-2024-4358.json)

**Risk Score**: 88/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 94.3%

**Summary**: In Progress Telerik Report Server, version 2024 Q1 (10.0.24.305) or earlier, on IIS, an unauthenticated attacker can gain access to Telerik Report Server restricted functionality via an authentication bypass vulnerability.

**Risk Factors**:

- CRITICAL severity
- 94.34% exploit probability

**Affected Vendors**: Progress Software Corporation, Report

**Tags**: `CWE-290`

**References**:

- [https://docs.telerik.com/report-server/knowledge-base/registration-auth-bypass-cve-2024-4358](https://docs.telerik.com/report-server/knowledge-base/registration-auth-bypass-cve-2024-4358)

---

### 11. [CVE-2024-34102](/api/vulns/CVE-2024-34102.json)

**Risk Score**: 88/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 94.3%

**Summary**: Adobe Commerce versions 2.4.7, 2.4.6-p5, 2.4.5-p7, 2.4.4-p8 and earlier are affected by an Improper Restriction of XML External Entity Reference ('XXE') vulnerability that could result in arbitrary code execution. An attacker could exploit this vulnerability by sending a crafted XML document that references external entities. Exploitation of this issue does not require user interaction.

**Risk Factors**:

- CRITICAL severity
- 94.34% exploit probability

**Affected Vendors**: Adobe

**Tags**: `CWE-611`

**References**:

- [https://helpx.adobe.com/security/products/magento/apsb24-40.html](https://helpx.adobe.com/security/products/magento/apsb24-40.html)
- [https://www.vicarius.io/vsociety/posts/cosmicsting-critical-unauthenticated-xxe-vulnerability-in-adobe-commerce-and-magento-cve-2024-34102](https://www.vicarius.io/vsociety/posts/cosmicsting-critical-unauthenticated-xxe-vulnerability-in-adobe-commerce-and-magento-cve-2024-34102)

---

### 12. [CVE-2024-1709](/api/vulns/CVE-2024-1709.json)

**Risk Score**: 88/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 94.3%

**Summary**: ConnectWise ScreenConnect 23.9.7 and prior are affected by an Authentication Bypass Using an Alternate Path or Channel

 vulnerability, which may allow an attacker direct access to confidential information or 

critical systems.



**Risk Factors**:

- CRITICAL severity
- 94.33% exploit probability

**Affected Vendors**: Connectwise

**Tags**: `CWE-288`

**References**:

- [https://www.connectwise.com/company/trust/security-bulletins/connectwise-screenconnect-23.9.8](https://www.connectwise.com/company/trust/security-bulletins/connectwise-screenconnect-23.9.8)
- [https://www.huntress.com/blog/vulnerability-reproduced-immediately-patch-screenconnect-23-9-8](https://www.huntress.com/blog/vulnerability-reproduced-immediately-patch-screenconnect-23-9-8)
- [https://www.huntress.com/blog/detection-guidance-for-connectwise-cwe-288-2](https://www.huntress.com/blog/detection-guidance-for-connectwise-cwe-288-2)

---

### 13. [CVE-2024-3400](/api/vulns/CVE-2024-3400.json)

**Risk Score**: 88/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 94.3%

**Summary**: A command injection as a result of arbitrary file creation vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS software for specific PAN-OS versions and distinct feature configurations may enable an unauthenticated attacker to execute arbitrary code with root privileges on the firewall.

Cloud NGFW, Panorama appliances, and Prisma Access are not impacted by this vulnerability.

**Risk Factors**:

- CRITICAL severity
- 94.32% exploit probability

**Affected Vendors**: Palo Alto Networks

**Tags**: `CWE-77`, `CWE-20`

**References**:

- [https://security.paloaltonetworks.com/CVE-2024-3400](https://security.paloaltonetworks.com/CVE-2024-3400)
- [https://unit42.paloaltonetworks.com/cve-2024-3400/](https://unit42.paloaltonetworks.com/cve-2024-3400/)
- [https://www.volexity.com/blog/2024/04/12/zero-day-exploitation-of-unauthenticated-remote-code-execution-vulnerability-in-globalprotect-cve-2024-3400/](https://www.volexity.com/blog/2024/04/12/zero-day-exploitation-of-unauthenticated-remote-code-execution-vulnerability-in-globalprotect-cve-2024-3400/)

---

### 14. [CVE-2024-23692](/api/vulns/CVE-2024-23692.json)

**Risk Score**: 88/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 94.3%

**Summary**: Rejetto HTTP File Server, up to and including version 2.3m, is vulnerable to a template injection vulnerability. This vulnerability allows a remote, unauthenticated attacker to execute arbitrary commands on the affected system by sending a specially crafted HTTP request. As of the CVE assignment date, Rejetto HFS 2.3m is no longer supported.

**Risk Factors**:

- CRITICAL severity
- 94.3% exploit probability

**Affected Vendors**: File, Rejetto

**Tags**: `CWE-1336`

**References**:

- [https://vulncheck.com/advisories/rejetto-unauth-rce](https://vulncheck.com/advisories/rejetto-unauth-rce)
- [https://mohemiv.com/all/rejetto-http-file-server-2-3m-unauthenticated-rce/](https://mohemiv.com/all/rejetto-http-file-server-2-3m-unauthenticated-rce/)
- [https://github.com/rapid7/metasploit-framework/pull/19240](https://github.com/rapid7/metasploit-framework/pull/19240)

---

### 15. [CVE-2024-51567](/api/vulns/CVE-2024-51567.json)

**Risk Score**: 88/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 94.3%

**Summary**: upgrademysqlstatus in databases/views.py in CyberPanel (aka Cyber Panel) before 5b08cd6 allows remote attackers to bypass authentication and execute arbitrary commands via /dataBases/upgrademysqlstatus by bypassing secMiddleware (which is only for a POST request) and using shell metacharacters in the statusfile property, as exploited in the wild in October 2024 by PSAUX. Versions through 2.3.6 and (unpatched) 2.3.7 are affected.

**Risk Factors**:

- CRITICAL severity
- 94.26% exploit probability

**Affected Vendors**: N/a

**References**:

- [https://cwe.mitre.org/data/definitions/78.html](https://cwe.mitre.org/data/definitions/78.html)
- [https://dreyand.rs/code/review/2024/10/27/what-are-my-options-cyberpanel-v236-pre-auth-rce](https://dreyand.rs/code/review/2024/10/27/what-are-my-options-cyberpanel-v236-pre-auth-rce)
- [https://github.com/usmannasir/cyberpanel/commit/5b08cd6d53f4dbc2107ad9f555122ce8b0996515](https://github.com/usmannasir/cyberpanel/commit/5b08cd6d53f4dbc2107ad9f555122ce8b0996515)

---

### 16. [CVE-2024-55591](/api/vulns/CVE-2024-55591.json)

**Risk Score**: 88/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.6 | 
**EPSS**: 94.2%

**Summary**: An Authentication Bypass Using an Alternate Path or Channel vulnerability [CWE-288] affecting FortiOS version 7.0.0 through 7.0.16 and FortiProxy version 7.0.0 through 7.0.19 and 7.2.0 through 7.2.12 allows a remote attacker to gain super-admin privileges via crafted requests to Node.js websocket module.

**Risk Factors**:

- CRITICAL severity
- 94.2% exploit probability
- Affects critical infrastructure: fortinet

**Affected Vendors**: Fortinet

**Tags**: `CWE-288`

**References**:

- [https://fortiguard.fortinet.com/psirt/FG-IR-24-535](https://fortiguard.fortinet.com/psirt/FG-IR-24-535)

---

### 17. [CVE-2024-4885](/api/vulns/CVE-2024-4885.json)

**Risk Score**: 88/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 94.2%

**Summary**: In WhatsUp Gold versions released before 2023.1.3, an unauthenticated Remote Code Execution vulnerability in Progress WhatsUpGold.  The 

WhatsUp.ExportUtilities.Export.GetFileWithoutZip



 allows execution of commands with iisapppool\nmconsole privileges.

**Risk Factors**:

- CRITICAL severity
- 94.2% exploit probability

**Affected Vendors**: Progress Software Corporation

**Tags**: `CWE-22`

**References**:

- [https://www.progress.com/network-monitoring](https://www.progress.com/network-monitoring)
- [https://community.progress.com/s/article/WhatsUp-Gold-Security-Bulletin-June-2024](https://community.progress.com/s/article/WhatsUp-Gold-Security-Bulletin-June-2024)

---

### 18. [CVE-2024-45519](/api/vulns/CVE-2024-45519.json)

**Risk Score**: 88/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 94.2%

**Summary**: The postjournal service in Zimbra Collaboration (ZCS) before 8.8.15 Patch 46, 9 before 9.0.0 Patch 41, 10 before 10.0.9, and 10.1 before 10.1.1 sometimes allows unauthenticated users to execute commands.

**Risk Factors**:

- CRITICAL severity
- 94.16% exploit probability

**Affected Vendors**: N/a

**References**:

- [https://wiki.zimbra.com/wiki/Security_Center](https://wiki.zimbra.com/wiki/Security_Center)
- [https://wiki.zimbra.com/wiki/Zimbra_Responsible_Disclosure_Policy](https://wiki.zimbra.com/wiki/Zimbra_Responsible_Disclosure_Policy)
- [https://wiki.zimbra.com/wiki/Zimbra_Releases/10.1.1#Security_Fixes](https://wiki.zimbra.com/wiki/Zimbra_Releases/10.1.1#Security_Fixes)

---

### 19. [CVE-2024-3272](/api/vulns/CVE-2024-3272.json)

**Risk Score**: 88/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 94.2%

**Summary**: ** UNSUPPORTED WHEN ASSIGNED ** A vulnerability, which was classified as very critical, has been found in D-Link DNS-320L, DNS-325, DNS-327L and DNS-340L up to 20240403. This issue affects some unknown processing of the file /cgi-bin/nas_sharing.cgi of the component HTTP GET Request Handler. The manipulation of the argument user with the input messagebus leads to hard-coded credentials. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The associ...

**Risk Factors**:

- CRITICAL severity
- 94.15% exploit probability

**Affected Vendors**: D-link

**Tags**: `CWE-798`

**References**:

- [https://vuldb.com/?id.259283](https://vuldb.com/?id.259283)
- [https://vuldb.com/?ctiid.259283](https://vuldb.com/?ctiid.259283)
- [https://github.com/netsecfish/dlink](https://github.com/netsecfish/dlink)

---

### 20. [CVE-2024-5217](/api/vulns/CVE-2024-5217.json)

**Risk Score**: 88/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 94.1%

**Summary**: ServiceNow has addressed an input validation vulnerability that was identified in the Washington DC, Vancouver, and earlier Now Platform releases. This vulnerability could enable an unauthenticated user to remotely execute code within the context of the Now Platform. The vulnerability is addressed in the listed patches and hot fixes below, which were released during the June 2024 patching cycle. If you have not done so already, we recommend applying security patches relevant to your instance as ...

**Risk Factors**:

- CRITICAL severity
- 94.11% exploit probability

**Affected Vendors**: Servicenow

**Tags**: `CWE-184`

**References**:

- [https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB1648313](https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB1648313)
- [https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB1644293](https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB1644293)
- [https://www.darkreading.com/cloud-security/patchnow-servicenow-critical-rce-bugs-active-exploit](https://www.darkreading.com/cloud-security/patchnow-servicenow-critical-rce-bugs-active-exploit)

---

### 21. [CVE-2024-13159](/api/vulns/CVE-2024-13159.json)

**Risk Score**: 88/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 93.9%

**Summary**: Absolute path traversal in Ivanti EPM before the 2024 January-2025 Security Update and 2022 SU6 January-2025 Security Update allows a remote unauthenticated attacker to leak sensitive information.

**Risk Factors**:

- CRITICAL severity
- 93.88% exploit probability

**Affected Vendors**: Ivanti

**Tags**: `CWE-36`

**References**:

- [https://forums.ivanti.com/s/article/Security-Advisory-EPM-January-2025-for-EPM-2024-and-EPM-2022-SU6](https://forums.ivanti.com/s/article/Security-Advisory-EPM-January-2025-for-EPM-2024-and-EPM-2022-SU6)

---

### 22. [CVE-2024-51378](/api/vulns/CVE-2024-51378.json)

**Risk Score**: 88/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 93.8%

**Summary**: getresetstatus in dns/views.py and ftp/views.py in CyberPanel (aka Cyber Panel) before 1c0c6cb allows remote attackers to bypass authentication and execute arbitrary commands via /dns/getresetstatus or /ftp/getresetstatus by bypassing secMiddleware (which is only for a POST request) and using shell metacharacters in the statusfile property, as exploited in the wild in October 2024 by PSAUX. Versions through 2.3.6 and (unpatched) 2.3.7 are affected.

**Risk Factors**:

- CRITICAL severity
- 93.84% exploit probability

**Affected Vendors**: N/a

**References**:

- [https://cwe.mitre.org/data/definitions/78.html](https://cwe.mitre.org/data/definitions/78.html)
- [https://github.com/usmannasir/cyberpanel/commit/1c0c6cbcf71abe573da0b5fddfb9603e7477f683](https://github.com/usmannasir/cyberpanel/commit/1c0c6cbcf71abe573da0b5fddfb9603e7477f683)
- [https://refr4g.github.io/posts/cyberpanel-command-injection-vulnerability/](https://refr4g.github.io/posts/cyberpanel-command-injection-vulnerability/)

---

### 23. [CVE-2024-21413](/api/vulns/CVE-2024-21413.json)

**Risk Score**: 88/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 93.8%

**Summary**: Microsoft Outlook Remote Code Execution Vulnerability

**Risk Factors**:

- CRITICAL severity
- 93.77% exploit probability
- Affects critical infrastructure: microsoft

**Affected Vendors**: Microsoft

**Tags**: `CWE-20`

**References**:

- [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21413](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21413)

---

### 24. [CVE-2024-12356](/api/vulns/CVE-2024-12356.json)

**Risk Score**: 88/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 93.7%

**Summary**: A critical vulnerability has been discovered in Privileged Remote Access (PRA) and Remote Support (RS) products which can allow an unauthenticated attacker to inject commands that are run as a site user.

**Risk Factors**:

- CRITICAL severity
- 93.69% exploit probability

**Affected Vendors**: Beyondtrust

**Tags**: `CWE-77`

**References**:

- [https://www.cve.org/CVERecord?id=CVE-2024-12356](https://www.cve.org/CVERecord?id=CVE-2024-12356)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-12356](https://nvd.nist.gov/vuln/detail/CVE-2024-12356)
- [https://www.beyondtrust.com/trust-center/security-advisories/bt24-10](https://www.beyondtrust.com/trust-center/security-advisories/bt24-10)

---

### 25. [CVE-2024-11680](/api/vulns/CVE-2024-11680.json)

**Risk Score**: 88/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 93.1%

**Summary**: ProjectSend versions prior to r1720 are affected by an improper authentication vulnerability. Remote, unauthenticated attackers can exploit this flaw by sending crafted HTTP requests to options.php, enabling unauthorized modification of the application's configuration. Successful exploitation allows attackers to create accounts, upload webshells, and embed malicious JavaScript.

**Risk Factors**:

- CRITICAL severity
- 93.11% exploit probability

**Affected Vendors**: Projectsend

**Tags**: `CWE-306`

**References**:

- [https://github.com/projectsend/projectsend/commit/193367d937b1a59ed5b68dd4e60bd53317473744](https://github.com/projectsend/projectsend/commit/193367d937b1a59ed5b68dd4e60bd53317473744)
- [https://www.synacktiv.com/sites/default/files/2024-07/synacktiv-projectsend-multiple-vulnerabilities.pdf](https://www.synacktiv.com/sites/default/files/2024-07/synacktiv-projectsend-multiple-vulnerabilities.pdf)
- [https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/http/projectsend_unauth_rce.rb](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/http/projectsend_unauth_rce.rb)

---

### 26. [CVE-2024-13160](/api/vulns/CVE-2024-13160.json)

**Risk Score**: 88/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 93.0%

**Summary**: Absolute path traversal in Ivanti EPM before the 2024 January-2025 Security Update and 2022 SU6 January-2025 Security Update allows a remote unauthenticated attacker to leak sensitive information.

**Risk Factors**:

- CRITICAL severity
- 92.97% exploit probability

**Affected Vendors**: Ivanti

**Tags**: `CWE-36`

**References**:

- [https://forums.ivanti.com/s/article/Security-Advisory-EPM-January-2025-for-EPM-2024-and-EPM-2022-SU6](https://forums.ivanti.com/s/article/Security-Advisory-EPM-January-2025-for-EPM-2024-and-EPM-2022-SU6)

---

### 27. [CVE-2024-21762](/api/vulns/CVE-2024-21762.json)

**Risk Score**: 88/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.6 | 
**EPSS**: 92.7%

**Summary**: A out-of-bounds write in Fortinet FortiOS versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.6, 7.0.0 through 7.0.13, 6.4.0 through 6.4.14, 6.2.0 through 6.2.15, 6.0.0 through 6.0.17, FortiProxy versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.8, 7.0.0 through 7.0.14, 2.0.0 through 2.0.13, 1.2.0 through 1.2.13, 1.1.0 through 1.1.6, 1.0.0 through 1.0.7 allows attacker to execute unauthorized code or commands via specifically crafted requests

**Risk Factors**:

- CRITICAL severity
- 92.69% exploit probability
- Affects critical infrastructure: fortinet

**Affected Vendors**: Fortinet

**Tags**: `CWE-787`

**References**:

- [https://fortiguard.com/psirt/FG-IR-24-015](https://fortiguard.com/psirt/FG-IR-24-015)

---

### 28. [CVE-2025-47812](/api/vulns/CVE-2025-47812.json)

**Risk Score**: 88/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 92.3%

**Summary**: In Wing FTP Server before 7.4.4. the user and admin web interfaces mishandle '\0' bytes, ultimately allowing injection of arbitrary Lua code into user session files. This can be used to execute arbitrary system commands with the privileges of the FTP service (root or SYSTEM by default). This is thus a remote code execution vulnerability that guarantees a total server compromise. This is also exploitable via anonymous FTP accounts.

**Risk Factors**:

- CRITICAL severity
- 92.26% exploit probability

**Affected Vendors**: Ftp, Total, Wftpserver

**Tags**: `CWE-158`

**References**:

- [https://www.wftpserver.com](https://www.wftpserver.com)
- [https://www.rcesecurity.com/2025/06/what-the-null-wing-ftp-server-rce-cve-2025-47812/](https://www.rcesecurity.com/2025/06/what-the-null-wing-ftp-server-rce-cve-2025-47812/)
- [https://www.vicarius.io/vsociety/posts/cve-2025-47812-mitigation-script-remote-code-execution-vulnerability-in-wing-ftp-server](https://www.vicarius.io/vsociety/posts/cve-2025-47812-mitigation-script-remote-code-execution-vulnerability-in-wing-ftp-server)

---

### 29. [CVE-2024-13161](/api/vulns/CVE-2024-13161.json)

**Risk Score**: 88/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 92.1%

**Summary**: Absolute path traversal in Ivanti EPM before the 2024 January-2025 Security Update and 2022 SU6 January-2025 Security Update allows a remote unauthenticated attacker to leak sensitive information.

**Risk Factors**:

- CRITICAL severity
- 92.14% exploit probability

**Affected Vendors**: Ivanti

**Tags**: `CWE-36`

**References**:

- [https://forums.ivanti.com/s/article/Security-Advisory-EPM-January-2025-for-EPM-2024-and-EPM-2022-SU6](https://forums.ivanti.com/s/article/Security-Advisory-EPM-January-2025-for-EPM-2024-and-EPM-2022-SU6)

---

### 30. [CVE-2025-3248](/api/vulns/CVE-2025-3248.json)

**Risk Score**: 88/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 92.0%

**Summary**: Langflow versions prior to 1.3.0 are susceptible to code injection in 
the /api/v1/validate/code endpoint. A remote and unauthenticated attacker can send crafted HTTP requests to execute arbitrary
code.

**Risk Factors**:

- CRITICAL severity
- 91.97% exploit probability

**Affected Vendors**: Langflow-ai

**Tags**: `CWE-306`

**References**:

- [https://github.com/langflow-ai/langflow/pull/6911](https://github.com/langflow-ai/langflow/pull/6911)
- [https://github.com/langflow-ai/langflow/releases/tag/1.3.0](https://github.com/langflow-ai/langflow/releases/tag/1.3.0)
- [https://www.horizon3.ai/attack-research/disclosures/unsafe-at-any-speed-abusing-python-exec-for-unauth-rce-in-langflow-ai/](https://www.horizon3.ai/attack-research/disclosures/unsafe-at-any-speed-abusing-python-exec-for-unauth-rce-in-langflow-ai/)

---

### 31. [CVE-2024-28987](/api/vulns/CVE-2024-28987.json)

**Risk Score**: 87/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.1 | 
**EPSS**: 94.3%

**Summary**: The SolarWinds Web Help Desk (WHD) software is affected by a hardcoded credential vulnerability, allowing remote unauthenticated user to access internal functionality and modify data.

**Risk Factors**:

- CRITICAL severity
- 94.29% exploit probability

**Affected Vendors**: Solarwinds

**Tags**: `CWE-798`

**References**:

- [https://www.solarwinds.com/trust-center/security-advisories/cve-2024-28987](https://www.solarwinds.com/trust-center/security-advisories/cve-2024-28987)
- [https://support.solarwinds.com/SuccessCenter/s/article/SolarWinds-Web-Help-Desk-12-8-3-Hotfix-2](https://support.solarwinds.com/SuccessCenter/s/article/SolarWinds-Web-Help-Desk-12-8-3-Hotfix-2)

---

### 32. [CVE-2025-0282](/api/vulns/CVE-2025-0282.json)

**Risk Score**: 87/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.0 | 
**EPSS**: 94.1%

**Summary**: A stack-based buffer overflow in Ivanti Connect Secure before version 22.7R2.5, Ivanti Policy Secure before version 22.7R1.2, and Ivanti Neurons for ZTA gateways before version 22.7R2.3 allows a remote unauthenticated attacker to achieve remote code execution.

**Risk Factors**:

- CRITICAL severity
- 94.11% exploit probability

**Affected Vendors**: Ivanti

**Tags**: `CWE-121`

**References**:

- [https://forums.ivanti.com/s/article/Security-Advisory-Ivanti-Connect-Secure-Policy-Secure-ZTA-Gateways-CVE-2025-0282-CVE-2025-0283](https://forums.ivanti.com/s/article/Security-Advisory-Ivanti-Connect-Secure-Policy-Secure-ZTA-Gateways-CVE-2025-0282-CVE-2025-0283)

---

### 33. [CVE-2024-20439](/api/vulns/CVE-2024-20439.json)

**Risk Score**: 87/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 87.9%

**Summary**: A vulnerability in Cisco Smart Licensing Utility (CSLU) could allow an unauthenticated, remote attacker to log into an affected system by using a static administrative credential.
 This vulnerability is due to an undocumented static user credential for an administrative account. An attacker could exploit this vulnerability by using the static credentials to login to the affected system. A successful exploit could allow the attacker to login to the affected system with administrative rights ove...

**Risk Factors**:

- CRITICAL severity
- 87.89% exploit probability
- Affects critical infrastructure: cisco

**Affected Vendors**: Cisco

**References**:

- [https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cslu-7gHMzWmw](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cslu-7gHMzWmw)

---

### 34. [CVE-2025-53770](/api/vulns/CVE-2025-53770.json)

**Risk Score**: 87/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 86.4%

**Summary**: Deserialization of untrusted data in on-premises Microsoft SharePoint Server allows an unauthorized attacker to execute code over a network.
Microsoft is aware that an exploit for CVE-2025-53770 exists in the wild.
Microsoft is preparing and fully testing a comprehensive update to address this vulnerability.  In the meantime, please make sure that the mitigation provided in this CVE documentation is in place so that you are protected from exploitation.

**Risk Factors**:

- CRITICAL severity
- 86.41% exploit probability
- Affects critical infrastructure: microsoft

**Affected Vendors**: Microsoft, Sharepoint

**Tags**: `CWE-502`

**References**:

- [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53770](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53770)

---

### 35. [CVE-2025-1316](/api/vulns/CVE-2025-1316.json)

**Risk Score**: 87/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 85.8%

**Summary**: Edimax IC-7100 does not properly neutralize requests. An attacker can create specially crafted requests to achieve remote code execution on the device

**Risk Factors**:

- CRITICAL severity
- 85.82% exploit probability

**Affected Vendors**: Edimax

**Tags**: `CWE-78`

**References**:

- [https://www.cisa.gov/news-events/ics-advisories/icsa-25-063-08](https://www.cisa.gov/news-events/ics-advisories/icsa-25-063-08)

---

### 36. [CVE-2025-31161](/api/vulns/CVE-2025-31161.json)

**Risk Score**: 87/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 84.4%

**Summary**: CrushFTP 10 before 10.8.4 and 11 before 11.3.1 allows authentication bypass and takeover of the crushadmin account (unless a DMZ proxy instance is used), as exploited in the wild in March and April 2025, aka "Unauthenticated HTTP(S) port access." A race condition exists in the AWS4-HMAC (compatible with S3) authorization method of the HTTP component of the FTP server. The server first verifies the existence of the user by performing a call to login_user_pass() with no password requirement. This ...

**Risk Factors**:

- CRITICAL severity
- 84.41% exploit probability

**Affected Vendors**: Crushftp, Ftp, The

**Tags**: `CWE-305`

**References**:

- [https://outpost24.com/blog/crushftp-auth-bypass-vulnerability/](https://outpost24.com/blog/crushftp-auth-bypass-vulnerability/)
- [https://crushftp.com/crush11wiki/Wiki.jsp?page=Update#section-Update-VulnerabilityInfo](https://crushftp.com/crush11wiki/Wiki.jsp?page=Update#section-Update-VulnerabilityInfo)

---

### 37. [CVE-2025-61882](/api/vulns/CVE-2025-61882.json)

**Risk Score**: 87/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 82.3%

**Summary**: Vulnerability in the Oracle Concurrent Processing product of Oracle E-Business Suite (component: BI Publisher Integration).  Supported versions that are affected are 12.2.3-12.2.14. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Concurrent Processing.  Successful attacks of this vulnerability can result in takeover of Oracle Concurrent Processing. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).  CV...

**Risk Factors**:

- CRITICAL severity
- 82.34% exploit probability
- Published within last month
- Affects critical infrastructure: oracle

**Affected Vendors**: Oracle

**References**:

- [https://www.oracle.com/security-alerts/alert-cve-2025-61882.html](https://www.oracle.com/security-alerts/alert-cve-2025-61882.html)

---

### 38. [CVE-2024-48248](/api/vulns/CVE-2024-48248.json)

**Risk Score**: 86/100 | 
**Severity**: HIGH | 
**CVSS**: 8.6 | 
**EPSS**: 94.0%

**Summary**: NAKIVO Backup & Replication before 11.0.0.88174 allows absolute path traversal for reading files via getImageByPath to /c/router (this may lead to remote code execution across the enterprise because PhysicalDiscovery has cleartext credentials).

**Risk Factors**:

- HIGH severity
- 93.99% exploit probability

**Affected Vendors**: Nakivo

**Tags**: `CWE-36`

**References**:

- [https://labs.watchtowr.com/the-best-security-is-when-we-all-agree-to-keep-everything-secret-except-the-secrets-nakivo-backup-replication-cve-2024-48248/](https://labs.watchtowr.com/the-best-security-is-when-we-all-agree-to-keep-everything-secret-except-the-secrets-nakivo-backup-replication-cve-2024-48248/)
- [https://helpcenter.nakivo.com/Release-Notes/Content/Release-Notes.htm](https://helpcenter.nakivo.com/Release-Notes/Content/Release-Notes.htm)

---

### 39. [CVE-2024-8956](/api/vulns/CVE-2024-8956.json)

**Risk Score**: 86/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.1 | 
**EPSS**: 86.5%

**Summary**: PTZOptics PT30X-SDI/NDI-xx before firmware 6.3.40 is vulnerable to an insufficient authentication issue. The camera does not properly enforce authentication to /cgi-bin/param.cgi when requests are sent without an HTTP Authorization header. The result is a remote and unauthenticated attacker can leak sensitive data such as usernames, password hashes, and configurations details. Additionally, the attacker can update individual configuration values or overwrite the whole file.

**Risk Factors**:

- CRITICAL severity
- 86.54% exploit probability

**Affected Vendors**: Ptzoptics

**Tags**: `CWE-306`

**References**:

- [https://ptzoptics.com/firmware-changelog/](https://ptzoptics.com/firmware-changelog/)
- [https://vulncheck.com/advisories/ptzoptics-insufficient-auth](https://vulncheck.com/advisories/ptzoptics-insufficient-auth)

---

### 40. [CVE-2024-6047](/api/vulns/CVE-2024-6047.json)

**Risk Score**: 86/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 74.9%

**Summary**: Certain EOL GeoVision devices fail to properly filter user input for the specific functionality. Unauthenticated remote attackers can exploit this vulnerability to inject and execute arbitrary system commands on the device.

**Risk Factors**:

- CRITICAL severity
- 74.88% exploit probability

**Affected Vendors**: Geovision

**Tags**: `CWE-78`

**References**:

- [https://www.twcert.org.tw/tw/cp-132-7883-f5635-1.html](https://www.twcert.org.tw/tw/cp-132-7883-f5635-1.html)
- [https://www.twcert.org.tw/en/cp-139-7884-c5a8b-2.html](https://www.twcert.org.tw/en/cp-139-7884-c5a8b-2.html)

---

### 41. [CVE-2024-11120](/api/vulns/CVE-2024-11120.json)

**Risk Score**: 85/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 63.5%

**Summary**: Certain EOL GeoVision devices have an OS Command Injection vulnerability. Unauthenticated remote attackers can exploit this vulnerability to inject and execute arbitrary system commands on the device. Moreover, this vulnerability has already been exploited by attackers, and we have received related reports.

**Risk Factors**:

- CRITICAL severity
- 63.47% exploit probability

**Affected Vendors**: Geovision

**Tags**: `CWE-78`

**References**:

- [https://www.twcert.org.tw/tw/cp-132-8236-d4836-1.html](https://www.twcert.org.tw/tw/cp-132-8236-d4836-1.html)
- [https://www.twcert.org.tw/en/cp-139-8237-26d7a-2.html](https://www.twcert.org.tw/en/cp-139-8237-26d7a-2.html)

---

### 42. [CVE-2025-32433](/api/vulns/CVE-2025-32433.json)

**Risk Score**: 85/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 62.9%

**Summary**: Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary w...

**Risk Factors**:

- CRITICAL severity
- 62.89% exploit probability

**Affected Vendors**: Erlang, Ssh

**Tags**: `CWE-306`

**References**:

- [https://github.com/erlang/otp/security/advisories/GHSA-37cp-fgq5-7wc2](https://github.com/erlang/otp/security/advisories/GHSA-37cp-fgq5-7wc2)
- [https://github.com/erlang/otp/commit/0fcd9c56524b28615e8ece65fc0c3f66ef6e4c12](https://github.com/erlang/otp/commit/0fcd9c56524b28615e8ece65fc0c3f66ef6e4c12)
- [https://github.com/erlang/otp/commit/6eef04130afc8b0ccb63c9a0d8650209cf54892f](https://github.com/erlang/otp/commit/6eef04130afc8b0ccb63c9a0d8650209cf54892f)

---

### 43. [CVE-2025-10035](/api/vulns/CVE-2025-10035.json)

**Risk Score**: 85/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 62.4%

**Summary**: A deserialization vulnerability in the License Servlet of Fortra's GoAnywhere MFT allows an actor with a validly forged license response signature to deserialize an arbitrary actor-controlled object, possibly leading to command injection.

**Risk Factors**:

- CRITICAL severity
- 62.44% exploit probability

**Affected Vendors**: Fortra

**Tags**: `CWE-77`, `CWE-502`

**References**:

- [https://www.fortra.com/security/advisories/product-security/fi-2025-012](https://www.fortra.com/security/advisories/product-security/fi-2025-012)

---

### 44. [CVE-2024-3273](/api/vulns/CVE-2024-3273.json)

**Risk Score**: 84/100 | 
**Severity**: HIGH | 
**CVSS**: 7.3 | 
**EPSS**: 94.4%

**Summary**: ** UNSUPPORTED WHEN ASSIGNED ** A vulnerability, which was classified as critical, was found in D-Link DNS-320L, DNS-325, DNS-327L and DNS-340L up to 20240403. Affected is an unknown function of the file /cgi-bin/nas_sharing.cgi of the component HTTP GET Request Handler. The manipulation of the argument system leads to command injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-259284. ...

**Risk Factors**:

- HIGH severity
- 94.43% exploit probability

**Affected Vendors**: D-link

**Tags**: `CWE-77`

**References**:

- [https://vuldb.com/?id.259284](https://vuldb.com/?id.259284)
- [https://vuldb.com/?ctiid.259284](https://vuldb.com/?ctiid.259284)
- [https://vuldb.com/?submit.304661](https://vuldb.com/?submit.304661)

---

### 45. [CVE-2024-12987](/api/vulns/CVE-2024-12987.json)

**Risk Score**: 83/100 | 
**Severity**: HIGH | 
**CVSS**: 7.3 | 
**EPSS**: 84.3%

**Summary**: A vulnerability, which was classified as critical, was found in DrayTek Vigor2960 and Vigor300B 1.5.1.4. Affected is an unknown function of the file /cgi-bin/mainfunction.cgi/apmcfgupload of the component Web Management Interface. The manipulation of the argument session leads to os command injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. Upgrading to version 1.5.1.5 is able to address this issue. It is recommended to upgrade ...

**Risk Factors**:

- HIGH severity
- 84.3% exploit probability

**Affected Vendors**: Draytek

**Tags**: `CWE-78`, `CWE-77`

**References**:

- [https://vuldb.com/?id.289380](https://vuldb.com/?id.289380)
- [https://vuldb.com/?ctiid.289380](https://vuldb.com/?ctiid.289380)
- [https://vuldb.com/?submit.468795](https://vuldb.com/?submit.468795)

---

### 46. [CVE-2024-28995](/api/vulns/CVE-2024-28995.json)

**Risk Score**: 79/100 | 
**Severity**: HIGH | 
**CVSS**: 8.6 | 
**EPSS**: 94.4%

**Summary**: 











SolarWinds Serv-U was susceptible to a directory transversal vulnerability that would allow access to read sensitive files on the host machine.    









**Risk Factors**:

- HIGH severity
- 94.38% exploit probability

**Affected Vendors**: Solarwinds

**Tags**: `CWE-22`

**References**:

- [https://www.solarwinds.com/trust-center/security-advisories/CVE-2024-28995](https://www.solarwinds.com/trust-center/security-advisories/CVE-2024-28995)

---

### 47. [CVE-2024-2389](/api/vulns/CVE-2024-2389.json)

**Risk Score**: 79/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 94.4%

**Summary**: In Flowmon versions prior to 11.1.14 and 12.3.5, an operating system command injection vulnerability has been identified.  An unauthenticated user can gain entry to the system via the Flowmon management interface, allowing for the execution of arbitrary system commands.



**Risk Factors**:

- CRITICAL severity
- 94.37% exploit probability

**Affected Vendors**: Progress Software

**Tags**: `CWE-78`

**References**:

- [https://www.flowmon.com](https://www.flowmon.com)
- [https://support.kemptechnologies.com/hc/en-us/articles/24878235038733-CVE-2024-2389-Flowmon-critical-security-vulnerability](https://support.kemptechnologies.com/hc/en-us/articles/24878235038733-CVE-2024-2389-Flowmon-critical-security-vulnerability)

---

### 48. [CVE-2024-24919](/api/vulns/CVE-2024-24919.json)

**Risk Score**: 79/100 | 
**Severity**: HIGH | 
**CVSS**: 8.6 | 
**EPSS**: 94.3%

**Summary**: Potentially allowing an attacker to read certain information on Check Point Security Gateways once connected to the internet and enabled with remote Access VPN or Mobile Access Software Blades. A Security fix that mitigates this vulnerability is available.

**Risk Factors**:

- HIGH severity
- 94.34% exploit probability

**Affected Vendors**: Checkpoint

**Tags**: `CWE-200`

**References**:

- [https://support.checkpoint.com/results/sk/sk182336](https://support.checkpoint.com/results/sk/sk182336)

---

### 49. [CVE-2024-31982](/api/vulns/CVE-2024-31982.json)

**Risk Score**: 79/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 94.3%

**Summary**: XWiki Platform is a generic wiki platform. Starting in version 2.4-milestone-1 and prior to versions 4.10.20, 15.5.4, and 15.10-rc-1, XWiki's database search allows remote code execution through the search text. This allows remote code execution for any visitor of a public wiki or user of a closed wiki as the database search is by default accessible for all users. This impacts the confidentiality, integrity and availability of the whole XWiki installation. This vulnerability has been patched in ...

**Risk Factors**:

- CRITICAL severity
- 94.31% exploit probability

**Affected Vendors**: The, Unless, Xwiki

**Tags**: `CWE-95`

**References**:

- [https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-2858-8cfx-69m9](https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-2858-8cfx-69m9)
- [https://github.com/xwiki/xwiki-platform/commit/3c9e4bb04286de94ad24854026a09fa967538e31](https://github.com/xwiki/xwiki-platform/commit/3c9e4bb04286de94ad24854026a09fa967538e31)
- [https://github.com/xwiki/xwiki-platform/commit/459e968be8740c8abc2a168196ce21e5ba93cfb8](https://github.com/xwiki/xwiki-platform/commit/459e968be8740c8abc2a168196ce21e5ba93cfb8)

---

### 50. [CVE-2024-5932](/api/vulns/CVE-2024-5932.json)

**Risk Score**: 79/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 94.1%

**Summary**: The GiveWP – Donation Plugin and Fundraising Platform plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 3.14.1 via deserialization of untrusted input from the 'give_title' parameter. This makes it possible for unauthenticated attackers to inject a PHP Object. The additional presence of a POP chain allows attackers to execute code remotely, and to delete arbitrary files.

**Risk Factors**:

- CRITICAL severity
- 94.13% exploit probability

**Affected Vendors**: Webdevmattcrom, WordPress

**Tags**: `CWE-502`

**References**:

- [https://www.wordfence.com/threat-intel/vulnerabilities/id/93e2d007-8157-42c5-92ad-704dc80749a3?source=cve](https://www.wordfence.com/threat-intel/vulnerabilities/id/93e2d007-8157-42c5-92ad-704dc80749a3?source=cve)
- [https://plugins.trac.wordpress.org/browser/give/tags/3.12.0/includes/login-register.php#L235](https://plugins.trac.wordpress.org/browser/give/tags/3.12.0/includes/login-register.php#L235)
- [https://plugins.trac.wordpress.org/browser/give/tags/3.12.0/includes/process-donation.php#L420](https://plugins.trac.wordpress.org/browser/give/tags/3.12.0/includes/process-donation.php#L420)

---

## Data Sources

This briefing was generated from the following sources:


---

*This briefing was automatically generated. For the complete dataset, visit the [vulnerability dashboard](/).*