---
title: Morning Vulnerability Briefing - 2025-06-30
date: 2025-06-30T13:58:49.675992
layout: layouts/post.njk
tags: [vulnerability, briefing, security]
vulnerabilityCount: 33026
criticalCount: 0
highCount: 0
---

# Morning Vulnerability Briefing - 2025-06-30

Today's briefing covers **33026 vulnerabilities** from 0 sources.

## Risk Distribution

- 🔴 **Critical Risk**: 0 vulnerabilities
- 🟠 **High Risk**: 0 vulnerabilities
- 🟡 **Medium Risk**: 11388 vulnerabilities
- 🟢 **Low Risk**: 21638 vulnerabilities

## Top Vulnerabilities

### 1. [CVE-2025-49113](/api/vulns/CVE-2025-49113.json)

**Risk Score**: 69/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.9 | 
**EPSS**: 76.3%

**Summary**: Roundcube Webmail before 1.5.10 and 1.6.x before 1.6.11 allows remote code execution by authenticated users because the _from parameter in a URL is not validated in program/actions/settings/upload.php, leading to PHP Object Deserialization.

**Risk Factors**:

- CRITICAL severity
- 76.28% exploit probability
- Published within last month

**Affected Vendors**: roundcube

**Tags**: `CWE-502`

**References**:

- [https://roundcube.net/news/2025/06/01/security-updates-1.6.11-and-1.5.10](https://roundcube.net/news/2025/06/01/security-updates-1.6.11-and-1.5.10)
- [https://github.com/roundcube/roundcubemail/pull/9865](https://github.com/roundcube/roundcubemail/pull/9865)
- [https://github.com/roundcube/roundcubemail/releases/tag/1.6.11](https://github.com/roundcube/roundcubemail/releases/tag/1.6.11)

---

### 2. [CVE-2024-55591](/api/vulns/CVE-2024-55591.json)

**Risk Score**: 68/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.6 | 
**EPSS**: 94.2%

**Summary**: An Authentication Bypass Using an Alternate Path or Channel vulnerability [CWE-288] affecting FortiOS version 7.0.0 through 7.0.16 and FortiProxy version 7.0.0 through 7.0.19 and 7.2.0 through 7.2.12 allows a remote attacker to gain super-admin privileges via crafted requests to Node.js websocket module.

**Risk Factors**:

- CRITICAL severity
- 94.18% exploit probability
- Affects critical infrastructure: fortinet

**Affected Vendors**: fortinet

**Tags**: `CWE-288`

**References**:

- [https://fortiguard.fortinet.com/psirt/FG-IR-24-535](https://fortiguard.fortinet.com/psirt/FG-IR-24-535)

---

### 3. [CVE-2024-21413](/api/vulns/CVE-2024-21413.json)

**Risk Score**: 67/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 93.7%

**Summary**: Microsoft Outlook Remote Code Execution Vulnerability

**Risk Factors**:

- CRITICAL severity
- 93.68% exploit probability
- Affects critical infrastructure: microsoft

**Affected Vendors**: microsoft

**Tags**: `CWE-20`

**References**:

- [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21413](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21413)

---

### 4. [CVE-2025-3248](/api/vulns/CVE-2025-3248.json)

**Risk Score**: 67/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 92.4%

**Summary**: Langflow versions prior to 1.3.0 are susceptible to code injection in 
the /api/v1/validate/code endpoint. A remote and unauthenticated attacker can send crafted HTTP requests to execute arbitrary
code.

**Risk Factors**:

- CRITICAL severity
- 92.39% exploit probability

**Affected Vendors**: langflow-ai

**Tags**: `CWE-306`

**References**:

- [https://github.com/langflow-ai/langflow/pull/6911](https://github.com/langflow-ai/langflow/pull/6911)
- [https://github.com/langflow-ai/langflow/releases/tag/1.3.0](https://github.com/langflow-ai/langflow/releases/tag/1.3.0)
- [https://www.horizon3.ai/attack-research/disclosures/unsafe-at-any-speed-abusing-python-exec-for-unauth-rce-in-langflow-ai/](https://www.horizon3.ai/attack-research/disclosures/unsafe-at-any-speed-abusing-python-exec-for-unauth-rce-in-langflow-ai/)

---

### 5. [CVE-2024-22320](/api/vulns/CVE-2024-22320.json)

**Risk Score**: 67/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 91.3%

**Summary**: IBM Operational Decision Manager 8.10.3 could allow a remote authenticated attacker to execute arbitrary code on the system, caused by an unsafe deserialization. By sending specially crafted request, an attacker could exploit this vulnerability to execute arbitrary code in the context of SYSTEM.  IBM X-Force ID:  279146.

**Risk Factors**:

- CRITICAL severity
- 91.3% exploit probability
- Affects critical infrastructure: ibm

**Affected Vendors**: ibm

**Tags**: `CWE-502`

**References**:

- [https://www.ibm.com/support/pages/node/7112382](https://www.ibm.com/support/pages/node/7112382)
- [https://exchange.xforce.ibmcloud.com/vulnerabilities/279146](https://exchange.xforce.ibmcloud.com/vulnerabilities/279146)

---

### 6. [CVE-2024-20419](/api/vulns/CVE-2024-20419.json)

**Risk Score**: 67/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 90.2%

**Summary**: A vulnerability in the authentication system of Cisco Smart Software Manager On-Prem (SSM On-Prem) could allow an unauthenticated, remote attacker to change the password of any user, including administrative users.
 This vulnerability is due to improper implementation of the password-change process. An attacker could exploit this vulnerability by sending crafted HTTP requests to an affected device. A successful exploit could allow an attacker to access the web UI or API with the privileges of ...

**Risk Factors**:

- CRITICAL severity
- 90.18% exploit probability
- Affects critical infrastructure: cisco

**Affected Vendors**: cisco

**References**:

- [https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cssm-auth-sLw3uhUy](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cssm-auth-sLw3uhUy)
- [https://www.secpod.com/blog/critical-flaw-in-ciscos-secure-email-gateways-allows-attackers-to-control-the-device-completely/](https://www.secpod.com/blog/critical-flaw-in-ciscos-secure-email-gateways-allows-attackers-to-control-the-device-completely/)

---

### 7. [CVE-2025-1974](/api/vulns/CVE-2025-1974.json)

**Risk Score**: 67/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 87.0%

**Summary**: A security issue was discovered in Kubernetes where under certain conditions, an unauthenticated attacker with access to the pod network can achieve arbitrary code execution in the context of the ingress-nginx controller. This can lead to disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)

**Risk Factors**:

- CRITICAL severity
- 87.05% exploit probability
- Affects critical infrastructure: kubernetes

**Affected Vendors**: kubernetes

**Tags**: `CWE-653`

**References**:

- [https://https://github.com/kubernetes/kubernetes/issues/131009](https://https://github.com/kubernetes/kubernetes/issues/131009)

---

### 8. [CVE-2025-32432](/api/vulns/CVE-2025-32432.json)

**Risk Score**: 67/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 82.7%

**Summary**: Craft is a flexible, user-friendly CMS for creating custom digital experiences on the web and beyond. Starting from version 3.0.0-RC1 to before 3.9.15, 4.0.0-RC1 to before 4.14.15, and 5.0.0-RC1 to before 5.6.17, Craft is vulnerable to remote code execution. This is a high-impact, low-complexity attack vector. This issue has been patched in versions 3.9.15, 4.14.15, and 5.6.17, and is an additional fix for CVE-2023-41892.

**Risk Factors**:

- CRITICAL severity
- 82.72% exploit probability

**Affected Vendors**: craftcms

**Tags**: `CWE-94`

**References**:

- [https://github.com/craftcms/cms/security/advisories/GHSA-f3gw-9ww9-jmc3](https://github.com/craftcms/cms/security/advisories/GHSA-f3gw-9ww9-jmc3)
- [https://github.com/craftcms/cms/commit/e1c85441fa47eeb7c688c2053f25419bc0547b47](https://github.com/craftcms/cms/commit/e1c85441fa47eeb7c688c2053f25419bc0547b47)
- [https://github.com/craftcms/cms/blob/3.x/CHANGELOG.md#3915---2025-04-10-critical](https://github.com/craftcms/cms/blob/3.x/CHANGELOG.md#3915---2025-04-10-critical)

---

### 9. [CVE-2024-4577](/api/vulns/CVE-2024-4577.json)

**Risk Score**: 66/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 94.4%

**Summary**: In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.

**Risk Factors**:

- CRITICAL severity
- 94.41% exploit probability

**Affected Vendors**: php group

**Tags**: `CWE-78`

**References**:

- [https://github.com/php/php-src/security/advisories/GHSA-3qgc-jrrr-25jv](https://github.com/php/php-src/security/advisories/GHSA-3qgc-jrrr-25jv)
- [https://blog.orange.tw/2024/06/cve-2024-4577-yet-another-php-rce.html](https://blog.orange.tw/2024/06/cve-2024-4577-yet-another-php-rce.html)
- [https://devco.re/blog/2024/06/06/security-alert-cve-2024-4577-php-cgi-argument-injection-vulnerability-en/](https://devco.re/blog/2024/06/06/security-alert-cve-2024-4577-php-cgi-argument-injection-vulnerability-en/)

---

### 10. [CVE-2024-50603](/api/vulns/CVE-2024-50603.json)

**Risk Score**: 66/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 94.3%

**Summary**: An issue was discovered in Aviatrix Controller before 7.1.4191 and 7.2.x before 7.2.4996. Due to the improper neutralization of special elements used in an OS command, an unauthenticated attacker is able to execute arbitrary code. Shell metacharacters can be sent to /v1/api in cloud_type for list_flightpath_destination_instances, or src_cloud_type for flightpath_connection_test.

**Risk Factors**:

- CRITICAL severity
- 94.35% exploit probability

**Affected Vendors**: aviatrix

**Tags**: `CWE-78`

**References**:

- [https://docs.aviatrix.com/documentation/latest/network-security/index.html](https://docs.aviatrix.com/documentation/latest/network-security/index.html)
- [https://docs.aviatrix.com/documentation/latest/release-notices/psirt-advisories/psirt-advisories.html?expand=true#remote-code-execution-vulnerability-in-aviatrix-controllers](https://docs.aviatrix.com/documentation/latest/release-notices/psirt-advisories/psirt-advisories.html?expand=true#remote-code-execution-vulnerability-in-aviatrix-controllers)
- [https://www.securing.pl/en/cve-2024-50603-aviatrix-network-controller-command-injection-vulnerability/](https://www.securing.pl/en/cve-2024-50603-aviatrix-network-controller-command-injection-vulnerability/)

---

### 11. [CVE-2024-1709](/api/vulns/CVE-2024-1709.json)

**Risk Score**: 66/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 94.3%

**Summary**: ConnectWise ScreenConnect 23.9.7 and prior are affected by an Authentication Bypass Using an Alternate Path or Channel

 vulnerability, which may allow an attacker direct access to confidential information or 

critical systems.



**Risk Factors**:

- CRITICAL severity
- 94.34% exploit probability

**Affected Vendors**: connectwise

**Tags**: `CWE-288`

**References**:

- [https://www.connectwise.com/company/trust/security-bulletins/connectwise-screenconnect-23.9.8](https://www.connectwise.com/company/trust/security-bulletins/connectwise-screenconnect-23.9.8)
- [https://www.huntress.com/blog/vulnerability-reproduced-immediately-patch-screenconnect-23-9-8](https://www.huntress.com/blog/vulnerability-reproduced-immediately-patch-screenconnect-23-9-8)
- [https://www.huntress.com/blog/detection-guidance-for-connectwise-cwe-288-2](https://www.huntress.com/blog/detection-guidance-for-connectwise-cwe-288-2)

---

### 12. [CVE-2024-10924](/api/vulns/CVE-2024-10924.json)

**Risk Score**: 66/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 93.6%

**Summary**: The Really Simple Security (Free, Pro, and Pro Multisite) plugins for WordPress are vulnerable to authentication bypass in versions 9.0.0 to 9.1.1.1. This is due to improper user check error handling in the two-factor REST API actions with the 'check_login_and_get_user' function. This makes it possible for unauthenticated attackers to log in as any existing user on the site, such as an administrator, when the "Two-Factor Authentication" setting is enabled (disabled by default).

**Risk Factors**:

- CRITICAL severity
- 93.63% exploit probability

**Affected Vendors**: rogierlankhorst, really simple plugins

**Tags**: `CWE-288`

**References**:

- [https://www.wordfence.com/threat-intel/vulnerabilities/id/7d5d05ad-1a7a-43d2-bbbf-597e975446be?source=cve](https://www.wordfence.com/threat-intel/vulnerabilities/id/7d5d05ad-1a7a-43d2-bbbf-597e975446be?source=cve)
- [https://plugins.trac.wordpress.org/browser/really-simple-ssl/tags/9.1.1.1/security/wordpress/two-fa/class-rsssl-two-factor-on-board-api.php#L67](https://plugins.trac.wordpress.org/browser/really-simple-ssl/tags/9.1.1.1/security/wordpress/two-fa/class-rsssl-two-factor-on-board-api.php#L67)
- [https://plugins.trac.wordpress.org/browser/really-simple-ssl/tags/9.1.1.1/security/wordpress/two-fa/class-rsssl-two-factor-on-board-api.php#L277](https://plugins.trac.wordpress.org/browser/really-simple-ssl/tags/9.1.1.1/security/wordpress/two-fa/class-rsssl-two-factor-on-board-api.php#L277)

---

### 13. [CVE-2025-24893](/api/vulns/CVE-2025-24893.json)

**Risk Score**: 66/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 92.4%

**Summary**: XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `<host>/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20se...

**Risk Factors**:

- CRITICAL severity
- 92.39% exploit probability

**Affected Vendors**: xwiki

**Tags**: `CWE-95`

**References**:

- [https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-rr6p-3pfg-562j](https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-rr6p-3pfg-562j)
- [https://github.com/xwiki/xwiki-platform/commit/67021db9b8ed26c2236a653269302a86bf01ef40](https://github.com/xwiki/xwiki-platform/commit/67021db9b8ed26c2236a653269302a86bf01ef40)
- [https://github.com/xwiki/xwiki-platform/blob/568447cad5172d97d6bbcfda9f6183689c2cf086/xwiki-platform-core/xwiki-platform-search/xwiki-platform-search-solr/xwiki-platform-search-solr-ui/src/main/resources/Main/SolrSearchMacros.xml#L955](https://github.com/xwiki/xwiki-platform/blob/568447cad5172d97d6bbcfda9f6183689c2cf086/xwiki-platform-core/xwiki-platform-search/xwiki-platform-search-solr/xwiki-platform-search-solr-ui/src/main/resources/Main/SolrSearchMacros.xml#L955)

---

### 14. [CVE-2024-21762](/api/vulns/CVE-2024-21762.json)

**Risk Score**: 66/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.6 | 
**EPSS**: 91.6%

**Summary**: A out-of-bounds write in Fortinet FortiOS versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.6, 7.0.0 through 7.0.13, 6.4.0 through 6.4.14, 6.2.0 through 6.2.15, 6.0.0 through 6.0.17, FortiProxy versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.8, 7.0.0 through 7.0.14, 2.0.0 through 2.0.13, 1.2.0 through 1.2.13, 1.1.0 through 1.1.6, 1.0.0 through 1.0.7 allows attacker to execute unauthorized code or commands via specifically crafted requests

**Risk Factors**:

- CRITICAL severity
- 91.6% exploit probability
- Affects critical infrastructure: fortinet

**Affected Vendors**: fortinet

**Tags**: `CWE-787`

**References**:

- [https://fortiguard.com/psirt/FG-IR-24-015](https://fortiguard.com/psirt/FG-IR-24-015)

---

### 15. [CVE-2024-47575](/api/vulns/CVE-2024-47575.json)

**Risk Score**: 66/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 90.3%

**Summary**: A missing authentication for critical function in FortiManager 7.6.0, FortiManager 7.4.0 through 7.4.4, FortiManager 7.2.0 through 7.2.7, FortiManager 7.0.0 through 7.0.12, FortiManager 6.4.0 through 6.4.14, FortiManager 6.2.0 through 6.2.12, Fortinet FortiManager Cloud 7.4.1 through 7.4.4, FortiManager Cloud 7.2.1 through 7.2.7, FortiManager Cloud 7.0.1 through 7.0.12, FortiManager Cloud 6.4.1 through 6.4.7 allows attacker to execute arbitrary code or commands via specially crafted requests.

**Risk Factors**:

- CRITICAL severity
- 90.31% exploit probability
- Affects critical infrastructure: fortinet

**Affected Vendors**: fortinet

**Tags**: `CWE-306`

**References**:

- [https://fortiguard.fortinet.com/psirt/FG-IR-24-423](https://fortiguard.fortinet.com/psirt/FG-IR-24-423)

---

### 16. [CVE-2024-20439](/api/vulns/CVE-2024-20439.json)

**Risk Score**: 66/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 88.9%

**Summary**: A vulnerability in Cisco Smart Licensing Utility (CSLU) could allow an unauthenticated, remote attacker to log into an affected system by using a static administrative credential.
 This vulnerability is due to an undocumented static user credential for an administrative account. An attacker could exploit this vulnerability by using the static credentials to login to the affected system. A successful exploit could allow the attacker to login to the affected system with administrative rights ove...

**Risk Factors**:

- CRITICAL severity
- 88.88% exploit probability
- Affects critical infrastructure: cisco

**Affected Vendors**: cisco

**References**:

- [https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cslu-7gHMzWmw](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cslu-7gHMzWmw)

---

### 17. [CVE-2025-47916](/api/vulns/CVE-2025-47916.json)

**Risk Score**: 66/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 87.9%

**Summary**: Invision Community 5.0.0 before 5.0.7 allows remote code execution via crafted template strings to themeeditor.php. The issue lies within the themeeditor controller (file: /applications/core/modules/front/system/themeeditor.php), where a protected method named customCss can be invoked by unauthenticated users. This method passes the value of the content parameter to the Theme::makeProcessFunction() method; hence it is evaluated by the template engine. Accordingly, this can be exploited by unauth...

**Risk Factors**:

- CRITICAL severity
- 87.91% exploit probability

**Affected Vendors**: invisioncommunity

**Tags**: `CWE-1336`

**References**:

- [https://invisioncommunity.com/release-notes-v5/507-r41/](https://invisioncommunity.com/release-notes-v5/507-r41/)
- [https://karmainsecurity.com/KIS-2025-02](https://karmainsecurity.com/KIS-2025-02)

---

### 18. [CVE-2024-4040](/api/vulns/CVE-2024-4040.json)

**Risk Score**: 65/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 94.4%

**Summary**: A server side template injection vulnerability in CrushFTP in all versions before 10.7.1 and 11.1.0 on all platforms allows unauthenticated remote attackers to read files from the filesystem outside of the VFS Sandbox, bypass authentication to gain administrative access, and perform remote code execution on the server.


**Risk Factors**:

- CRITICAL severity
- 94.43% exploit probability

**Affected Vendors**: crushftp

**Tags**: `CWE-1336`

**References**:

- [https://www.crushftp.com/crush11wiki/Wiki.jsp?page=Update](https://www.crushftp.com/crush11wiki/Wiki.jsp?page=Update)
- [https://www.crushftp.com/crush10wiki/Wiki.jsp?page=Update](https://www.crushftp.com/crush10wiki/Wiki.jsp?page=Update)
- [https://www.reddit.com/r/cybersecurity/comments/1c850i2/all_versions_of_crush_ftp_are_vulnerable/](https://www.reddit.com/r/cybersecurity/comments/1c850i2/all_versions_of_crush_ftp_are_vulnerable/)

---

### 19. [CVE-2024-36401](/api/vulns/CVE-2024-36401.json)

**Risk Score**: 65/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 94.4%

**Summary**: GeoServer is an open source server that allows users to share and edit geospatial data. Prior to versions 2.22.6, 2.23.6, 2.24.4, and 2.25.2, multiple OGC request parameters allow Remote Code Execution (RCE) by unauthenticated users through specially crafted input against a default GeoServer installation due to unsafely evaluating property names as XPath expressions.

The GeoTools library API that GeoServer calls evaluates property/attribute names for feature types in a way that unsafely passes ...

**Risk Factors**:

- CRITICAL severity
- 94.42% exploit probability

**Affected Vendors**: geoserver

**Tags**: `CWE-95`

**References**:

- [https://github.com/geoserver/geoserver/security/advisories/GHSA-6jj6-gm7p-fcvv](https://github.com/geoserver/geoserver/security/advisories/GHSA-6jj6-gm7p-fcvv)
- [https://github.com/geotools/geotools/security/advisories/GHSA-w3pj-wh35-fq8w](https://github.com/geotools/geotools/security/advisories/GHSA-w3pj-wh35-fq8w)
- [https://github.com/geotools/geotools/pull/4797](https://github.com/geotools/geotools/pull/4797)

---

### 20. [CVE-2024-1212](/api/vulns/CVE-2024-1212.json)

**Risk Score**: 65/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 94.3%

**Summary**: Unauthenticated remote attackers can access the system through the LoadMaster management interface, enabling arbitrary system command execution.




**Risk Factors**:

- CRITICAL severity
- 94.35% exploit probability

**Affected Vendors**: progress software

**Tags**: `CWE-78`

**References**:

- [https://kemptechnologies.com/](https://kemptechnologies.com/)
- [https://freeloadbalancer.com/](https://freeloadbalancer.com/)
- [https://support.kemptechnologies.com/hc/en-us/articles/24325072850573-Release-Notice-LMOS-7-2-59-2-7-2-54-8-7-2-48-10-CVE-2024-1212](https://support.kemptechnologies.com/hc/en-us/articles/24325072850573-Release-Notice-LMOS-7-2-59-2-7-2-54-8-7-2-48-10-CVE-2024-1212)

---

### 21. [CVE-2024-3400](/api/vulns/CVE-2024-3400.json)

**Risk Score**: 65/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 94.3%

**Summary**: A command injection as a result of arbitrary file creation vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS software for specific PAN-OS versions and distinct feature configurations may enable an unauthenticated attacker to execute arbitrary code with root privileges on the firewall.

Cloud NGFW, Panorama appliances, and Prisma Access are not impacted by this vulnerability.

**Risk Factors**:

- CRITICAL severity
- 94.29% exploit probability

**Affected Vendors**: palo alto networks

**Tags**: `CWE-77`, `CWE-20`

**References**:

- [https://security.paloaltonetworks.com/CVE-2024-3400](https://security.paloaltonetworks.com/CVE-2024-3400)
- [https://unit42.paloaltonetworks.com/cve-2024-3400/](https://unit42.paloaltonetworks.com/cve-2024-3400/)
- [https://www.volexity.com/blog/2024/04/12/zero-day-exploitation-of-unauthenticated-remote-code-execution-vulnerability-in-globalprotect-cve-2024-3400/](https://www.volexity.com/blog/2024/04/12/zero-day-exploitation-of-unauthenticated-remote-code-execution-vulnerability-in-globalprotect-cve-2024-3400/)

---

### 22. [CVE-2024-51567](/api/vulns/CVE-2024-51567.json)

**Risk Score**: 65/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 94.3%

**Summary**: upgrademysqlstatus in databases/views.py in CyberPanel (aka Cyber Panel) before 5b08cd6 allows remote attackers to bypass authentication and execute arbitrary commands via /dataBases/upgrademysqlstatus by bypassing secMiddleware (which is only for a POST request) and using shell metacharacters in the statusfile property, as exploited in the wild in October 2024 by PSAUX. Versions through 2.3.6 and (unpatched) 2.3.7 are affected.

**Risk Factors**:

- CRITICAL severity
- 94.26% exploit probability

**Affected Vendors**: n/a

**References**:

- [https://cwe.mitre.org/data/definitions/78.html](https://cwe.mitre.org/data/definitions/78.html)
- [https://dreyand.rs/code/review/2024/10/27/what-are-my-options-cyberpanel-v236-pre-auth-rce](https://dreyand.rs/code/review/2024/10/27/what-are-my-options-cyberpanel-v236-pre-auth-rce)
- [https://github.com/usmannasir/cyberpanel/commit/5b08cd6d53f4dbc2107ad9f555122ce8b0996515](https://github.com/usmannasir/cyberpanel/commit/5b08cd6d53f4dbc2107ad9f555122ce8b0996515)

---

### 23. [CVE-2024-31982](/api/vulns/CVE-2024-31982.json)

**Risk Score**: 65/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 94.2%

**Summary**: XWiki Platform is a generic wiki platform. Starting in version 2.4-milestone-1 and prior to versions 4.10.20, 15.5.4, and 15.10-rc-1, XWiki's database search allows remote code execution through the search text. This allows remote code execution for any visitor of a public wiki or user of a closed wiki as the database search is by default accessible for all users. This impacts the confidentiality, integrity and availability of the whole XWiki installation. This vulnerability has been patched in ...

**Risk Factors**:

- CRITICAL severity
- 94.16% exploit probability

**Affected Vendors**: xwiki

**Tags**: `CWE-95`

**References**:

- [https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-2858-8cfx-69m9](https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-2858-8cfx-69m9)
- [https://github.com/xwiki/xwiki-platform/commit/3c9e4bb04286de94ad24854026a09fa967538e31](https://github.com/xwiki/xwiki-platform/commit/3c9e4bb04286de94ad24854026a09fa967538e31)
- [https://github.com/xwiki/xwiki-platform/commit/459e968be8740c8abc2a168196ce21e5ba93cfb8](https://github.com/xwiki/xwiki-platform/commit/459e968be8740c8abc2a168196ce21e5ba93cfb8)

---

### 24. [CVE-2024-45519](/api/vulns/CVE-2024-45519.json)

**Risk Score**: 65/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 94.2%

**Summary**: The postjournal service in Zimbra Collaboration (ZCS) before 8.8.15 Patch 46, 9 before 9.0.0 Patch 41, 10 before 10.0.9, and 10.1 before 10.1.1 sometimes allows unauthenticated users to execute commands.

**Risk Factors**:

- CRITICAL severity
- 94.15% exploit probability

**Affected Vendors**: n/a

**References**:

- [https://wiki.zimbra.com/wiki/Security_Center](https://wiki.zimbra.com/wiki/Security_Center)
- [https://wiki.zimbra.com/wiki/Zimbra_Responsible_Disclosure_Policy](https://wiki.zimbra.com/wiki/Zimbra_Responsible_Disclosure_Policy)
- [https://wiki.zimbra.com/wiki/Zimbra_Releases/10.1.1#Security_Fixes](https://wiki.zimbra.com/wiki/Zimbra_Releases/10.1.1#Security_Fixes)

---

### 25. [CVE-2024-5932](/api/vulns/CVE-2024-5932.json)

**Risk Score**: 65/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 94.1%

**Summary**: The GiveWP – Donation Plugin and Fundraising Platform plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 3.14.1 via deserialization of untrusted input from the 'give_title' parameter. This makes it possible for unauthenticated attackers to inject a PHP Object. The additional presence of a POP chain allows attackers to execute code remotely, and to delete arbitrary files.

**Risk Factors**:

- CRITICAL severity
- 94.1% exploit probability

**Affected Vendors**: webdevmattcrom

**Tags**: `CWE-502`

**References**:

- [https://www.wordfence.com/threat-intel/vulnerabilities/id/93e2d007-8157-42c5-92ad-704dc80749a3?source=cve](https://www.wordfence.com/threat-intel/vulnerabilities/id/93e2d007-8157-42c5-92ad-704dc80749a3?source=cve)
- [https://plugins.trac.wordpress.org/browser/give/tags/3.12.0/includes/login-register.php#L235](https://plugins.trac.wordpress.org/browser/give/tags/3.12.0/includes/login-register.php#L235)
- [https://plugins.trac.wordpress.org/browser/give/tags/3.12.0/includes/process-donation.php#L420](https://plugins.trac.wordpress.org/browser/give/tags/3.12.0/includes/process-donation.php#L420)

---

### 26. [CVE-2024-51378](/api/vulns/CVE-2024-51378.json)

**Risk Score**: 65/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 94.1%

**Summary**: getresetstatus in dns/views.py and ftp/views.py in CyberPanel (aka Cyber Panel) before 1c0c6cb allows remote attackers to bypass authentication and execute arbitrary commands via /dns/getresetstatus or /ftp/getresetstatus by bypassing secMiddleware (which is only for a POST request) and using shell metacharacters in the statusfile property, as exploited in the wild in October 2024 by PSAUX. Versions through 2.3.6 and (unpatched) 2.3.7 are affected.

**Risk Factors**:

- CRITICAL severity
- 94.09% exploit probability

**Affected Vendors**: n/a

**References**:

- [https://cwe.mitre.org/data/definitions/78.html](https://cwe.mitre.org/data/definitions/78.html)
- [https://github.com/usmannasir/cyberpanel/commit/1c0c6cbcf71abe573da0b5fddfb9603e7477f683](https://github.com/usmannasir/cyberpanel/commit/1c0c6cbcf71abe573da0b5fddfb9603e7477f683)
- [https://refr4g.github.io/posts/cyberpanel-command-injection-vulnerability/](https://refr4g.github.io/posts/cyberpanel-command-injection-vulnerability/)

---

### 27. [CVE-2025-29927](/api/vulns/CVE-2025-29927.json)

**Risk Score**: 65/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.1 | 
**EPSS**: 93.6%

**Summary**: Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed ...

**Risk Factors**:

- CRITICAL severity
- 93.64% exploit probability

**Affected Vendors**: vercel

**Tags**: `CWE-285`

**References**:

- [https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw](https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw)
- [https://github.com/vercel/next.js/commit/52a078da3884efe6501613c7834a3d02a91676d2](https://github.com/vercel/next.js/commit/52a078da3884efe6501613c7834a3d02a91676d2)
- [https://github.com/vercel/next.js/commit/5fd3ae8f8542677c6294f32d18022731eab6fe48](https://github.com/vercel/next.js/commit/5fd3ae8f8542677c6294f32d18022731eab6fe48)

---

### 28. [CVE-2024-11680](/api/vulns/CVE-2024-11680.json)

**Risk Score**: 65/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 93.6%

**Summary**: ProjectSend versions prior to r1720 are affected by an improper authentication vulnerability. Remote, unauthenticated attackers can exploit this flaw by sending crafted HTTP requests to options.php, enabling unauthorized modification of the application's configuration. Successful exploitation allows attackers to create accounts, upload webshells, and embed malicious JavaScript.

**Risk Factors**:

- CRITICAL severity
- 93.61% exploit probability

**Affected Vendors**: projectsend

**Tags**: `CWE-287`

**References**:

- [https://github.com/projectsend/projectsend/commit/193367d937b1a59ed5b68dd4e60bd53317473744](https://github.com/projectsend/projectsend/commit/193367d937b1a59ed5b68dd4e60bd53317473744)
- [https://www.synacktiv.com/sites/default/files/2024-07/synacktiv-projectsend-multiple-vulnerabilities.pdf](https://www.synacktiv.com/sites/default/files/2024-07/synacktiv-projectsend-multiple-vulnerabilities.pdf)
- [https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/http/projectsend_unauth_rce.rb](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/http/projectsend_unauth_rce.rb)

---

### 29. [CVE-2024-25600](/api/vulns/CVE-2024-25600.json)

**Risk Score**: 65/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 93.5%

**Summary**: Improper Control of Generation of Code ('Code Injection') vulnerability in Codeer Limited Bricks Builder allows Code Injection.This issue affects Bricks Builder: from n/a through 1.9.6.

**Risk Factors**:

- CRITICAL severity
- 93.45% exploit probability

**Affected Vendors**: codeer limited

**Tags**: `CWE-94`

**References**:

- [https://patchstack.com/database/vulnerability/bricks/wordpress-bricks-theme-1-9-6-unauthenticated-remote-code-execution-rce-vulnerability?_s_id=cve](https://patchstack.com/database/vulnerability/bricks/wordpress-bricks-theme-1-9-6-unauthenticated-remote-code-execution-rce-vulnerability?_s_id=cve)
- [https://snicco.io/vulnerability-disclosure/bricks/unauthenticated-rce-in-bricks-1-9-6](https://snicco.io/vulnerability-disclosure/bricks/unauthenticated-rce-in-bricks-1-9-6)
- [https://patchstack.com/articles/critical-rce-patched-in-bricks-builder-theme?_s_id=cve](https://patchstack.com/articles/critical-rce-patched-in-bricks-builder-theme?_s_id=cve)

---

### 30. [CVE-2024-23108](/api/vulns/CVE-2024-23108.json)

**Risk Score**: 65/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.7 | 
**EPSS**: 88.6%

**Summary**: An improper neutralization of special elements used in an os command ('os command injection') in Fortinet FortiSIEM version 7.1.0 through 7.1.1 and 7.0.0 through 7.0.2 and 6.7.0 through 6.7.8 and 6.6.0 through 6.6.3 and 6.5.0 through 6.5.2 and 6.4.0 through 6.4.2 allows attacker to execute unauthorized code or commands via via crafted API requests.

**Risk Factors**:

- CRITICAL severity
- 88.63% exploit probability
- Affects critical infrastructure: fortinet

**Affected Vendors**: fortinet

**Tags**: `CWE-78`

**References**:

- [https://fortiguard.com/psirt/FG-IR-23-130](https://fortiguard.com/psirt/FG-IR-23-130)

---

### 31. [CVE-2024-38063](/api/vulns/CVE-2024-38063.json)

**Risk Score**: 65/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 88.1%

**Summary**: Windows TCP/IP Remote Code Execution Vulnerability

**Risk Factors**:

- CRITICAL severity
- 88.1% exploit probability
- Affects critical infrastructure: microsoft

**Affected Vendors**: microsoft

**Tags**: `CWE-191`

**References**:

- [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38063](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38063)

---

### 32. [CVE-2025-1661](/api/vulns/CVE-2025-1661.json)

**Risk Score**: 65/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 87.3%

**Summary**: The HUSKY – Products Filter Professional for WooCommerce plugin for WordPress is vulnerable to Local File Inclusion in all versions up to, and including, 1.3.6.5 via the 'template' parameter of the woof_text_search AJAX action. This makes it possible for unauthenticated attackers to include and execute arbitrary files on the server, allowing the execution of any PHP code in those files. This can be used to bypass access controls, obtain sensitive data, or achieve code execution in cases where im...

**Risk Factors**:

- CRITICAL severity
- 87.31% exploit probability

**Affected Vendors**: realmag777

**Tags**: `CWE-22`

**References**:

- [https://www.wordfence.com/threat-intel/vulnerabilities/id/9ae7b6fc-2120-4573-8b1b-d5422d435fa5?source=cve](https://www.wordfence.com/threat-intel/vulnerabilities/id/9ae7b6fc-2120-4573-8b1b-d5422d435fa5?source=cve)
- [https://plugins.trac.wordpress.org/browser/woocommerce-products-filter/trunk/ext/by_text/index.php](https://plugins.trac.wordpress.org/browser/woocommerce-products-filter/trunk/ext/by_text/index.php)
- [https://plugins.trac.wordpress.org/changeset?sfp_email=&sfph_mail=&reponame=&old=3253169%40woocommerce-products-filter&new=3253169%40woocommerce-products-filter&sfp_email=&sfph_mail=](https://plugins.trac.wordpress.org/changeset?sfp_email=&sfph_mail=&reponame=&old=3253169%40woocommerce-products-filter&new=3253169%40woocommerce-products-filter&sfp_email=&sfph_mail=)

---

### 33. [CVE-2024-49112](/api/vulns/CVE-2024-49112.json)

**Risk Score**: 65/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 87.1%

**Summary**: Windows Lightweight Directory Access Protocol (LDAP) Remote Code Execution Vulnerability

**Risk Factors**:

- CRITICAL severity
- 87.12% exploit probability
- Affects critical infrastructure: microsoft

**Affected Vendors**: microsoft

**Tags**: `CWE-190`

**References**:

- [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49112](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49112)

---

### 34. [CVE-2024-38077](/api/vulns/CVE-2024-38077.json)

**Risk Score**: 65/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 83.5%

**Summary**: Windows Remote Desktop Licensing Service Remote Code Execution Vulnerability

**Risk Factors**:

- CRITICAL severity
- 83.55% exploit probability
- Affects critical infrastructure: microsoft

**Affected Vendors**: microsoft

**Tags**: `CWE-122`

**References**:

- [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38077](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38077)

---

### 35. [CVE-2024-3272](/api/vulns/CVE-2024-3272.json)

**Risk Score**: 64/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 94.2%

**Summary**: ** UNSUPPORTED WHEN ASSIGNED ** A vulnerability, which was classified as very critical, has been found in D-Link DNS-320L, DNS-325, DNS-327L and DNS-340L up to 20240403. This issue affects some unknown processing of the file /cgi-bin/nas_sharing.cgi of the component HTTP GET Request Handler. The manipulation of the argument user with the input messagebus leads to hard-coded credentials. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The associ...

**Risk Factors**:

- CRITICAL severity
- 94.22% exploit probability

**Affected Vendors**: d-link

**Tags**: `CWE-798`

**References**:

- [https://vuldb.com/?id.259283](https://vuldb.com/?id.259283)
- [https://vuldb.com/?ctiid.259283](https://vuldb.com/?ctiid.259283)
- [https://github.com/netsecfish/dlink](https://github.com/netsecfish/dlink)

---

### 36. [CVE-2024-13159](/api/vulns/CVE-2024-13159.json)

**Risk Score**: 64/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 94.1%

**Summary**: Absolute path traversal in Ivanti EPM before the 2024 January-2025 Security Update and 2022 SU6 January-2025 Security Update allows a remote unauthenticated attacker to leak sensitive information.

**Risk Factors**:

- CRITICAL severity
- 94.12% exploit probability

**Affected Vendors**: ivanti

**Tags**: `CWE-36`

**References**:

- [https://forums.ivanti.com/s/article/Security-Advisory-EPM-January-2025-for-EPM-2024-and-EPM-2022-SU6](https://forums.ivanti.com/s/article/Security-Advisory-EPM-January-2025-for-EPM-2024-and-EPM-2022-SU6)

---

### 37. [CVE-2024-13160](/api/vulns/CVE-2024-13160.json)

**Risk Score**: 64/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 93.5%

**Summary**: Absolute path traversal in Ivanti EPM before the 2024 January-2025 Security Update and 2022 SU6 January-2025 Security Update allows a remote unauthenticated attacker to leak sensitive information.

**Risk Factors**:

- CRITICAL severity
- 93.51% exploit probability

**Affected Vendors**: ivanti

**Tags**: `CWE-36`

**References**:

- [https://forums.ivanti.com/s/article/Security-Advisory-EPM-January-2025-for-EPM-2024-and-EPM-2022-SU6](https://forums.ivanti.com/s/article/Security-Advisory-EPM-January-2025-for-EPM-2024-and-EPM-2022-SU6)

---

### 38. [CVE-2024-21650](/api/vulns/CVE-2024-21650.json)

**Risk Score**: 64/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 93.4%

**Summary**: XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. XWiki is vulnerable to a remote code execution (RCE) attack through its user registration feature. This issue allows an attacker to execute arbitrary code by crafting malicious payloads in the "first name" or "last name" fields during user registration. This impacts all installations that have user registration enabled for guests. This vulnerability has been patched in XWiki 14.10.17, 15.5.3 ...

**Risk Factors**:

- CRITICAL severity
- 93.4% exploit probability

**Affected Vendors**: xwiki

**Tags**: `CWE-95`

**References**:

- [https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-rj7p-xjv7-7229](https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-rj7p-xjv7-7229)
- [https://github.com/xwiki/xwiki-platform/commit/b290bfd573c6f7db6cc15a88dd4111d9fcad0d31](https://github.com/xwiki/xwiki-platform/commit/b290bfd573c6f7db6cc15a88dd4111d9fcad0d31)
- [https://jira.xwiki.org/browse/XWIKI-21173](https://jira.xwiki.org/browse/XWIKI-21173)

---

### 39. [CVE-2024-0204](/api/vulns/CVE-2024-0204.json)

**Risk Score**: 64/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 93.3%

**Summary**: Authentication bypass in Fortra's GoAnywhere MFT prior to 7.4.1 allows an unauthorized user to create an admin user via the administration portal.

**Risk Factors**:

- CRITICAL severity
- 93.33% exploit probability

**Affected Vendors**: fortra

**Tags**: `CWE-425`

**References**:

- [https://www.fortra.com/security/advisory/fi-2024-001](https://www.fortra.com/security/advisory/fi-2024-001)
- [https://my.goanywhere.com/webclient/ViewSecurityAdvisories.xhtml](https://my.goanywhere.com/webclient/ViewSecurityAdvisories.xhtml)
- [http://packetstormsecurity.com/files/176683/GoAnywhere-MFT-Authentication-Bypass.html](http://packetstormsecurity.com/files/176683/GoAnywhere-MFT-Authentication-Bypass.html)

---

### 40. [CVE-2024-3495](/api/vulns/CVE-2024-3495.json)

**Risk Score**: 64/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 93.3%

**Summary**: The Country State City Dropdown CF7 plugin for WordPress is vulnerable to SQL Injection via the ‘cnt’ and 'sid' parameters in versions up to, and including, 2.7.2 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

**Risk Factors**:

- CRITICAL severity
- 93.3% exploit probability

**Affected Vendors**: trustyplugins

**References**:

- [https://www.wordfence.com/threat-intel/vulnerabilities/id/17dcacaf-0e2a-4bef-b944-fb7e43d25777?source=cve](https://www.wordfence.com/threat-intel/vulnerabilities/id/17dcacaf-0e2a-4bef-b944-fb7e43d25777?source=cve)
- [https://plugins.trac.wordpress.org/browser/country-state-city-auto-dropdown/trunk/includes/ajax-actions.php#L8](https://plugins.trac.wordpress.org/browser/country-state-city-auto-dropdown/trunk/includes/ajax-actions.php#L8)
- [https://plugins.trac.wordpress.org/browser/country-state-city-auto-dropdown/trunk/includes/ajax-actions.php#L22](https://plugins.trac.wordpress.org/browser/country-state-city-auto-dropdown/trunk/includes/ajax-actions.php#L22)

---

### 41. [CVE-2024-29895](/api/vulns/CVE-2024-29895.json)

**Risk Score**: 64/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 92.7%

**Summary**: Cacti provides an operational monitoring and fault management framework. A command injection vulnerability on the 1.3.x DEV branch allows any unauthenticated user to execute arbitrary command on the server when `register_argc_argv` option of PHP is `On`. In `cmd_realtime.php` line 119, the `$poller_id` used as part of the command execution is sourced from `$_SERVER['argv']`, which can be controlled by URL when `register_argc_argv` option of PHP is `On`. And this option is `On` by default in many...

**Risk Factors**:

- CRITICAL severity
- 92.65% exploit probability

**Affected Vendors**: cacti

**Tags**: `CWE-77`

**References**:

- [https://github.com/Cacti/cacti/security/advisories/GHSA-cr28-x256-xf5m](https://github.com/Cacti/cacti/security/advisories/GHSA-cr28-x256-xf5m)
- [https://github.com/Cacti/cacti/commit/53e8014d1f082034e0646edc6286cde3800c683d](https://github.com/Cacti/cacti/commit/53e8014d1f082034e0646edc6286cde3800c683d)
- [https://github.com/Cacti/cacti/commit/99633903cad0de5ace636249de16f77e57a3c8fc](https://github.com/Cacti/cacti/commit/99633903cad0de5ace636249de16f77e57a3c8fc)

---

### 42. [CVE-2024-32651](/api/vulns/CVE-2024-32651.json)

**Risk Score**: 64/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 92.5%

**Summary**: changedetection.io is an open source web page change detection, website watcher, restock monitor and notification service. There is a Server Side Template Injection (SSTI) in Jinja2 that allows Remote Command Execution on the server host. Attackers can run any system command without any restriction and they could use a reverse shell. The impact is critical as the attacker can completely takeover the server machine. This can be reduced if changedetection is behind a login page, but this isn't req...

**Risk Factors**:

- CRITICAL severity
- 92.52% exploit probability

**Affected Vendors**: dgtlmoon

**Tags**: `CWE-1336`

**References**:

- [https://github.com/dgtlmoon/changedetection.io/security/advisories/GHSA-4r7v-whpg-8rx3](https://github.com/dgtlmoon/changedetection.io/security/advisories/GHSA-4r7v-whpg-8rx3)
- [https://github.com/dgtlmoon/changedetection.io/releases/tag/0.45.21](https://github.com/dgtlmoon/changedetection.io/releases/tag/0.45.21)
- [https://www.onsecurity.io/blog/server-side-template-injection-with-jinja2](https://www.onsecurity.io/blog/server-side-template-injection-with-jinja2)

---

### 43. [CVE-2024-9234](/api/vulns/CVE-2024-9234.json)

**Risk Score**: 64/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 92.5%

**Summary**: The GutenKit – Page Builder Blocks, Patterns, and Templates for Gutenberg Block Editor plugin for WordPress is vulnerable to arbitrary file uploads due to a missing capability check on the install_and_activate_plugin_from_external() function  (install-active-plugin REST API endpoint) in all versions up to, and including, 2.1.0. This makes it possible for unauthenticated attackers to install and activate arbitrary plugins, or utilize the functionality to upload arbitrary files spoofed like plugin...

**Risk Factors**:

- CRITICAL severity
- 92.5% exploit probability

**Affected Vendors**: ataurr

**Tags**: `CWE-862`

**References**:

- [https://www.wordfence.com/threat-intel/vulnerabilities/id/e44c5dc0-6bf6-417a-9383-b345ff57ac32?source=cve](https://www.wordfence.com/threat-intel/vulnerabilities/id/e44c5dc0-6bf6-417a-9383-b345ff57ac32?source=cve)
- [https://github.com/WordPressBugBounty/plugins-gutenkit-blocks-addon/blob/dc3738bb821cf1d93a11379b8695793fa5e1b9e6/gutenkit-blocks-addon/includes/Admin/Api/ActivePluginData.php#L76](https://github.com/WordPressBugBounty/plugins-gutenkit-blocks-addon/blob/dc3738bb821cf1d93a11379b8695793fa5e1b9e6/gutenkit-blocks-addon/includes/Admin/Api/ActivePluginData.php#L76)
- [https://plugins.trac.wordpress.org/browser/gutenkit-blocks-addon/tags/2.1.0/includes/Admin/Api/ActivePluginData.php?rev=3159783#L76](https://plugins.trac.wordpress.org/browser/gutenkit-blocks-addon/tags/2.1.0/includes/Admin/Api/ActivePluginData.php?rev=3159783#L76)

---

### 44. [CVE-2024-1071](/api/vulns/CVE-2024-1071.json)

**Risk Score**: 64/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 92.0%

**Summary**: The Ultimate Member – User Profile, Registration, Login, Member Directory, Content Restriction & Membership Plugin plugin for WordPress is vulnerable to SQL Injection via the 'sorting' parameter in versions 2.1.3 to 2.8.2 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive i...

**Risk Factors**:

- CRITICAL severity
- 91.99% exploit probability

**Affected Vendors**: ultimatemember

**References**:

- [https://www.wordfence.com/threat-intel/vulnerabilities/id/005fa621-3c49-4c23-add5-d6b7a9110055?source=cve](https://www.wordfence.com/threat-intel/vulnerabilities/id/005fa621-3c49-4c23-add5-d6b7a9110055?source=cve)
- [https://plugins.trac.wordpress.org/browser/ultimate-member/tags/2.8.2/includes/core/class-member-directory-meta.php?rev=3022076](https://plugins.trac.wordpress.org/browser/ultimate-member/tags/2.8.2/includes/core/class-member-directory-meta.php?rev=3022076)
- [https://plugins.trac.wordpress.org/browser/ultimate-member/tags/2.8.2/includes/core/class-member-directory-meta.php?rev=3022076#L666](https://plugins.trac.wordpress.org/browser/ultimate-member/tags/2.8.2/includes/core/class-member-directory-meta.php?rev=3022076#L666)

---

### 45. [CVE-2024-8856](/api/vulns/CVE-2024-8856.json)

**Risk Score**: 64/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 91.9%

**Summary**: The Backup and Staging by WP Time Capsule plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the the UploadHandler.php file and no direct file access prevention in all versions up to, and including, 1.22.21. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

**Risk Factors**:

- CRITICAL severity
- 91.92% exploit probability

**Affected Vendors**: revmakx

**Tags**: `CWE-434`

**References**:

- [https://www.wordfence.com/threat-intel/vulnerabilities/id/fdc2de78-5601-461f-b2f0-c80b592ccb1b?source=cve](https://www.wordfence.com/threat-intel/vulnerabilities/id/fdc2de78-5601-461f-b2f0-c80b592ccb1b?source=cve)
- [https://plugins.trac.wordpress.org/browser/wp-time-capsule/trunk/wp-tcapsule-bridge/upload/php/UploadHandler.php](https://plugins.trac.wordpress.org/browser/wp-time-capsule/trunk/wp-tcapsule-bridge/upload/php/UploadHandler.php)
- [https://plugins.trac.wordpress.org/changeset/3188325/](https://plugins.trac.wordpress.org/changeset/3188325/)

---

### 46. [CVE-2024-46986](/api/vulns/CVE-2024-46986.json)

**Risk Score**: 64/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 88.2%

**Summary**: Camaleon CMS is a dynamic and advanced content management system based on Ruby on Rails. An arbitrary file write vulnerability accessible via the upload method of the MediaController allows authenticated users to write arbitrary files to any location on the web server Camaleon CMS is running on (depending on the permissions of the underlying filesystem). E.g. This can lead to a delayed remote code execution in case an attacker is able to write a Ruby file into the config/initializers/ subfolder ...

**Risk Factors**:

- CRITICAL severity
- 88.21% exploit probability

**Affected Vendors**: owen2345

**Tags**: `CWE-74`

**References**:

- [https://github.com/owen2345/camaleon-cms/security/advisories/GHSA-wmjg-vqhv-q5p5](https://github.com/owen2345/camaleon-cms/security/advisories/GHSA-wmjg-vqhv-q5p5)
- [https://codeql.github.com/codeql-query-help/ruby/rb-path-injection](https://codeql.github.com/codeql-query-help/ruby/rb-path-injection)
- [https://owasp.org/www-community/attacks/Path_Traversal](https://owasp.org/www-community/attacks/Path_Traversal)

---

### 47. [CVE-2024-36404](/api/vulns/CVE-2024-36404.json)

**Risk Score**: 64/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 85.5%

**Summary**: GeoTools is an open source Java library that provides tools for geospatial data. Prior to versions 31.2, 30.4, and 29.6, Remote Code Execution (RCE) is possible if an application uses certain GeoTools functionality to evaluate XPath expressions supplied by user input. Versions 31.2, 30.4, and 29.6 contain a fix for this issue. As a workaround, GeoTools can operate with reduced functionality by removing the `gt-complex` jar from one's application. As an example of the impact, application schema `...

**Risk Factors**:

- CRITICAL severity
- 85.45% exploit probability

**Affected Vendors**: geotools

**Tags**: `CWE-95`

**References**:

- [https://github.com/geotools/geotools/security/advisories/GHSA-w3pj-wh35-fq8w](https://github.com/geotools/geotools/security/advisories/GHSA-w3pj-wh35-fq8w)
- [https://github.com/geotools/geotools/pull/4797](https://github.com/geotools/geotools/pull/4797)
- [https://github.com/geotools/geotools/commit/f0c9961dc4d40c5acfce2169fab92805738de5ea](https://github.com/geotools/geotools/commit/f0c9961dc4d40c5acfce2169fab92805738de5ea)

---

### 48. [CVE-2025-31161](/api/vulns/CVE-2025-31161.json)

**Risk Score**: 64/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 83.3%

**Summary**: CrushFTP 10 before 10.8.4 and 11 before 11.3.1 allows authentication bypass and takeover of the crushadmin account (unless a DMZ proxy instance is used), as exploited in the wild in March and April 2025, aka "Unauthenticated HTTP(S) port access." A race condition exists in the AWS4-HMAC (compatible with S3) authorization method of the HTTP component of the FTP server. The server first verifies the existence of the user by performing a call to login_user_pass() with no password requirement. This ...

**Risk Factors**:

- CRITICAL severity
- 83.27% exploit probability

**Affected Vendors**: crushftp

**Tags**: `CWE-305`

**References**:

- [https://outpost24.com/blog/crushftp-auth-bypass-vulnerability/](https://outpost24.com/blog/crushftp-auth-bypass-vulnerability/)
- [https://crushftp.com/crush11wiki/Wiki.jsp?page=Update#section-Update-VulnerabilityInfo](https://crushftp.com/crush11wiki/Wiki.jsp?page=Update#section-Update-VulnerabilityInfo)

---

### 49. [CVE-2025-27007](/api/vulns/CVE-2025-27007.json)

**Risk Score**: 64/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 81.8%

**Summary**: Incorrect Privilege Assignment vulnerability in Brainstorm Force SureTriggers allows Privilege Escalation.This issue affects SureTriggers: from n/a through 1.0.82.

**Risk Factors**:

- CRITICAL severity
- 81.78% exploit probability

**Affected Vendors**: brainstorm force

**Tags**: `CWE-266`

**References**:

- [https://patchstack.com/database/wordpress/plugin/suretriggers/vulnerability/wordpress-suretriggers-1-0-82-privilege-escalation-vulnerability?_s_id=cve](https://patchstack.com/database/wordpress/plugin/suretriggers/vulnerability/wordpress-suretriggers-1-0-82-privilege-escalation-vulnerability?_s_id=cve)
- [https://patchstack.com/articles/additional-critical-ottokit-formerly-suretriggers-vulnerability-patched?_s_id=cve](https://patchstack.com/articles/additional-critical-ottokit-formerly-suretriggers-vulnerability-patched?_s_id=cve)

---

### 50. [CVE-2024-24576](/api/vulns/CVE-2024-24576.json)

**Risk Score**: 64/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 81.4%

**Summary**: Rust is a programming language. The Rust Security Response WG was notified that the Rust standard library prior to version 1.77.2 did not properly escape arguments when invoking batch files (with the `bat` and `cmd` extensions) on Windows using the `Command`. An attacker able to control the arguments passed to the spawned process could execute arbitrary shell commands by bypassing the escaping. The severity of this vulnerability is critical for those who invoke batch files on Windows with untrus...

**Risk Factors**:

- CRITICAL severity
- 81.37% exploit probability

**Affected Vendors**: rust-lang

**Tags**: `CWE-78`, `CWE-88`

**References**:

- [https://github.com/rust-lang/rust/security/advisories/GHSA-q455-m56c-85mh](https://github.com/rust-lang/rust/security/advisories/GHSA-q455-m56c-85mh)
- [https://doc.rust-lang.org/std/io/enum.ErrorKind.html#variant.InvalidInput](https://doc.rust-lang.org/std/io/enum.ErrorKind.html#variant.InvalidInput)
- [https://doc.rust-lang.org/std/os/windows/process/trait.CommandExt.html#tymethod.raw_arg](https://doc.rust-lang.org/std/os/windows/process/trait.CommandExt.html#tymethod.raw_arg)

---

### 51. [CVE-2024-43468](/api/vulns/CVE-2024-43468.json)

**Risk Score**: 64/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 78.8%

**Summary**: Microsoft Configuration Manager Remote Code Execution Vulnerability

**Risk Factors**:

- CRITICAL severity
- 78.76% exploit probability
- Affects critical infrastructure: microsoft

**Affected Vendors**: microsoft

**Tags**: `CWE-89`

**References**:

- [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43468](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43468)

---

### 52. [CVE-2025-21298](/api/vulns/CVE-2025-21298.json)

**Risk Score**: 64/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 70.6%

**Summary**: Windows OLE Remote Code Execution Vulnerability

**Risk Factors**:

- CRITICAL severity
- 70.56% exploit probability
- Affects critical infrastructure: microsoft

**Affected Vendors**: microsoft

**Tags**: `CWE-416`

**References**:

- [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-21298](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-21298)

---

### 53. [CVE-2024-27198](/api/vulns/CVE-2024-27198.json)

**Risk Score**: 63/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 94.6%

**Summary**: In JetBrains TeamCity before 2023.11.4 authentication bypass allowing to perform admin actions was possible

**Risk Factors**:

- CRITICAL severity
- 94.57% exploit probability

**Affected Vendors**: jetbrains

**References**:

- [https://www.jetbrains.com/privacy-security/issues-fixed/](https://www.jetbrains.com/privacy-security/issues-fixed/)
- [https://www.darkreading.com/cyberattacks-data-breaches/jetbrains-teamcity-mass-exploitation-underway-rogue-accounts-thrive](https://www.darkreading.com/cyberattacks-data-breaches/jetbrains-teamcity-mass-exploitation-underway-rogue-accounts-thrive)

---

### 54. [CVE-2024-2389](/api/vulns/CVE-2024-2389.json)

**Risk Score**: 63/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 94.3%

**Summary**: In Flowmon versions prior to 11.1.14 and 12.3.5, an operating system command injection vulnerability has been identified.  An unauthenticated user can gain entry to the system via the Flowmon management interface, allowing for the execution of arbitrary system commands.



**Risk Factors**:

- CRITICAL severity
- 94.35% exploit probability

**Affected Vendors**: progress software

**Tags**: `CWE-78`

**References**:

- [https://www.flowmon.com](https://www.flowmon.com)
- [https://support.kemptechnologies.com/hc/en-us/articles/24878235038733-CVE-2024-2389-Flowmon-critical-security-vulnerability](https://support.kemptechnologies.com/hc/en-us/articles/24878235038733-CVE-2024-2389-Flowmon-critical-security-vulnerability)

---

### 55. [CVE-2024-4879](/api/vulns/CVE-2024-4879.json)

**Risk Score**: 63/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 94.3%

**Summary**: ServiceNow has addressed an input validation vulnerability that was identified in Vancouver and Washington DC Now Platform releases. This vulnerability could enable an unauthenticated user to remotely execute code within the context of the Now Platform. ServiceNow applied an update to hosted instances, and ServiceNow released the update to our partners and self-hosted customers. Listed below are the patches and hot fixes that address the vulnerability. If you have not done so already, we recomme...

**Risk Factors**:

- CRITICAL severity
- 94.34% exploit probability

**Affected Vendors**: servicenow

**Tags**: `CWE-1287`

**References**:

- [https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB1645154](https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB1645154)
- [https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB1644293](https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB1644293)
- [https://www.darkreading.com/cloud-security/patchnow-servicenow-critical-rce-bugs-active-exploit](https://www.darkreading.com/cloud-security/patchnow-servicenow-critical-rce-bugs-active-exploit)

---

### 56. [CVE-2024-23692](/api/vulns/CVE-2024-23692.json)

**Risk Score**: 63/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 94.3%

**Summary**: Rejetto HTTP File Server, up to and including version 2.3m, is vulnerable to a template injection vulnerability. This vulnerability allows a remote, unauthenticated attacker to execute arbitrary commands on the affected system by sending a specially crafted HTTP request. As of the CVE assignment date, Rejetto HFS 2.3m is no longer supported.

**Risk Factors**:

- CRITICAL severity
- 94.28% exploit probability

**Affected Vendors**: rejetto

**Tags**: `CWE-1336`

**References**:

- [https://vulncheck.com/advisories/rejetto-unauth-rce](https://vulncheck.com/advisories/rejetto-unauth-rce)
- [https://mohemiv.com/all/rejetto-http-file-server-2-3m-unauthenticated-rce/](https://mohemiv.com/all/rejetto-http-file-server-2-3m-unauthenticated-rce/)
- [https://github.com/rapid7/metasploit-framework/pull/19240](https://github.com/rapid7/metasploit-framework/pull/19240)

---

### 57. [CVE-2024-5217](/api/vulns/CVE-2024-5217.json)

**Risk Score**: 63/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 94.2%

**Summary**: ServiceNow has addressed an input validation vulnerability that was identified in the Washington DC, Vancouver, and earlier Now Platform releases. This vulnerability could enable an unauthenticated user to remotely execute code within the context of the Now Platform. The vulnerability is addressed in the listed patches and hot fixes below, which were released during the June 2024 patching cycle. If you have not done so already, we recommend applying security patches relevant to your instance as ...

**Risk Factors**:

- CRITICAL severity
- 94.2% exploit probability

**Affected Vendors**: servicenow

**Tags**: `CWE-184`

**References**:

- [https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB1648313](https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB1648313)
- [https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB1644293](https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB1644293)
- [https://www.darkreading.com/cloud-security/patchnow-servicenow-critical-rce-bugs-active-exploit](https://www.darkreading.com/cloud-security/patchnow-servicenow-critical-rce-bugs-active-exploit)

---

### 58. [CVE-2024-1698](/api/vulns/CVE-2024-1698.json)

**Risk Score**: 63/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 93.9%

**Summary**: The NotificationX – Best FOMO, Social Proof, WooCommerce Sales Popup & Notification Bar Plugin With Elementor plugin for WordPress is vulnerable to SQL Injection via the 'type' parameter in all versions up to, and including, 2.8.2 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract se...

**Risk Factors**:

- CRITICAL severity
- 93.88% exploit probability

**Affected Vendors**: wpdevteam

**References**:

- [https://www.wordfence.com/threat-intel/vulnerabilities/id/e110ea99-e2fa-4558-bcf3-942a35af0b91?source=cve](https://www.wordfence.com/threat-intel/vulnerabilities/id/e110ea99-e2fa-4558-bcf3-942a35af0b91?source=cve)
- [https://plugins.trac.wordpress.org/changeset/3040809/notificationx/trunk/includes/Core/Database.php](https://plugins.trac.wordpress.org/changeset/3040809/notificationx/trunk/includes/Core/Database.php)
- [https://plugins.trac.wordpress.org/changeset/3040809/notificationx/trunk/includes/Core/Rest/Analytics.php](https://plugins.trac.wordpress.org/changeset/3040809/notificationx/trunk/includes/Core/Rest/Analytics.php)

---

### 59. [CVE-2024-28255](/api/vulns/CVE-2024-28255.json)

**Risk Score**: 63/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 93.8%

**Summary**: OpenMetadata is a unified platform for discovery, observability, and governance powered by a central metadata repository, in-depth lineage, and seamless team collaboration. The `JwtFilter` handles the API authentication by requiring and verifying JWT tokens. When a new request comes in, the request's path is checked against this list. When the request's path contains any of the excluded endpoints the filter returns without validating the JWT. Unfortunately, an attacker may use Path Parameters to...

**Risk Factors**:

- CRITICAL severity
- 93.8% exploit probability

**Affected Vendors**: open-metadata

**Tags**: `CWE-287`

**References**:

- [https://github.com/open-metadata/OpenMetadata/security/advisories/GHSA-6wx7-qw5p-wh84](https://github.com/open-metadata/OpenMetadata/security/advisories/GHSA-6wx7-qw5p-wh84)
- [https://github.com/open-metadata/OpenMetadata/blob/e2043a3f31312ebb42391d6c93a67584d798de52/openmetadata-service/src/main/java/org/openmetadata/service/security/JwtFilter.java#L111](https://github.com/open-metadata/OpenMetadata/blob/e2043a3f31312ebb42391d6c93a67584d798de52/openmetadata-service/src/main/java/org/openmetadata/service/security/JwtFilter.java#L111)
- [https://github.com/open-metadata/OpenMetadata/blob/e2043a3f31312ebb42391d6c93a67584d798de52/openmetadata-service/src/main/java/org/openmetadata/service/security/JwtFilter.java#L113](https://github.com/open-metadata/OpenMetadata/blob/e2043a3f31312ebb42391d6c93a67584d798de52/openmetadata-service/src/main/java/org/openmetadata/service/security/JwtFilter.java#L113)

---

### 60. [CVE-2024-7954](/api/vulns/CVE-2024-7954.json)

**Risk Score**: 63/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 93.8%

**Summary**: The porte_plume plugin used by SPIP before 4.30-alpha2, 4.2.13, and 4.1.16 is vulnerable to an arbitrary code execution vulnerability. A remote and unauthenticated attacker can execute arbitrary PHP as the SPIP user by sending a crafted HTTP request.

**Risk Factors**:

- CRITICAL severity
- 93.77% exploit probability

**Affected Vendors**: spip

**Tags**: `CWE-284`

**References**:

- [https://vulncheck.com/advisories/spip-porte-plume](https://vulncheck.com/advisories/spip-porte-plume)
- [https://blog.spip.net/Mise-a-jour-critique-de-securite-sortie-de-SPIP-4-3-0-alpha2-SPIP-4-2-13-SPIP-4.html](https://blog.spip.net/Mise-a-jour-critique-de-securite-sortie-de-SPIP-4-3-0-alpha2-SPIP-4-2-13-SPIP-4.html)
- [https://thinkloveshare.com/hacking/spip_preauth_rce_2024_part_1_the_feather/](https://thinkloveshare.com/hacking/spip_preauth_rce_2024_part_1_the_feather/)

---

### 61. [CVE-2024-12356](/api/vulns/CVE-2024-12356.json)

**Risk Score**: 63/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 93.6%

**Summary**: A critical vulnerability has been discovered in Privileged Remote Access (PRA) and Remote Support (RS) products which can allow an unauthenticated attacker to inject commands that are run as a site user.

**Risk Factors**:

- CRITICAL severity
- 93.59% exploit probability

**Affected Vendors**: beyondtrust

**Tags**: `CWE-77`

**References**:

- [https://www.cve.org/CVERecord?id=CVE-2024-12356](https://www.cve.org/CVERecord?id=CVE-2024-12356)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-12356](https://nvd.nist.gov/vuln/detail/CVE-2024-12356)
- [https://www.beyondtrust.com/trust-center/security-advisories/bt24-10](https://www.beyondtrust.com/trust-center/security-advisories/bt24-10)

---

### 62. [CVE-2024-27956](/api/vulns/CVE-2024-27956.json)

**Risk Score**: 63/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.9 | 
**EPSS**: 93.5%

**Summary**: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in ValvePress Automatic allows SQL Injection.This issue affects Automatic: from n/a through 3.92.0.



**Risk Factors**:

- CRITICAL severity
- 93.46% exploit probability

**Affected Vendors**: valvepress

**Tags**: `CWE-89`

**References**:

- [https://patchstack.com/database/vulnerability/wp-automatic/wordpress-automatic-plugin-3-92-0-unauthenticated-arbitrary-sql-execution-vulnerability?_s_id=cve](https://patchstack.com/database/vulnerability/wp-automatic/wordpress-automatic-plugin-3-92-0-unauthenticated-arbitrary-sql-execution-vulnerability?_s_id=cve)
- [https://patchstack.com/articles/critical-vulnerabilities-patched-in-wordpress-automatic-plugin?_s_id=cve](https://patchstack.com/articles/critical-vulnerabilities-patched-in-wordpress-automatic-plugin?_s_id=cve)

---

### 63. [CVE-2024-4443](/api/vulns/CVE-2024-4443.json)

**Risk Score**: 63/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 93.4%

**Summary**: The Business Directory Plugin – Easy Listing Directories for WordPress plugin for WordPress is vulnerable to time-based SQL Injection via the ‘listingfields’ parameter in all versions up to, and including, 6.4.2 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information...

**Risk Factors**:

- CRITICAL severity
- 93.38% exploit probability

**Affected Vendors**: strategy11team

**References**:

- [https://www.wordfence.com/threat-intel/vulnerabilities/id/982fb304-08d6-4195-97a3-f18e94295492?source=cve](https://www.wordfence.com/threat-intel/vulnerabilities/id/982fb304-08d6-4195-97a3-f18e94295492?source=cve)
- [https://plugins.trac.wordpress.org/browser/business-directory-plugin/trunk/includes/fields/class-fieldtypes-select.php#L110](https://plugins.trac.wordpress.org/browser/business-directory-plugin/trunk/includes/fields/class-fieldtypes-select.php#L110)
- [https://plugins.trac.wordpress.org/changeset/3089626/](https://plugins.trac.wordpress.org/changeset/3089626/)

---

### 64. [CVE-2024-13161](/api/vulns/CVE-2024-13161.json)

**Risk Score**: 63/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 92.1%

**Summary**: Absolute path traversal in Ivanti EPM before the 2024 January-2025 Security Update and 2022 SU6 January-2025 Security Update allows a remote unauthenticated attacker to leak sensitive information.

**Risk Factors**:

- CRITICAL severity
- 92.14% exploit probability

**Affected Vendors**: ivanti

**Tags**: `CWE-36`

**References**:

- [https://forums.ivanti.com/s/article/Security-Advisory-EPM-January-2025-for-EPM-2024-and-EPM-2022-SU6](https://forums.ivanti.com/s/article/Security-Advisory-EPM-January-2025-for-EPM-2024-and-EPM-2022-SU6)

---

### 65. [CVE-2025-24016](/api/vulns/CVE-2025-24016.json)

**Risk Score**: 63/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.9 | 
**EPSS**: 91.8%

**Summary**: Wazuh is a free and open source platform used for threat prevention, detection, and response. Starting in version 4.4.0 and prior to version 4.9.1, an unsafe deserialization vulnerability allows for remote code execution on Wazuh servers. DistributedAPI parameters are a serialized as JSON and deserialized using `as_wazuh_object` (in `framework/wazuh/core/cluster/common.py`). If an attacker manages to inject an unsanitized dictionary in DAPI request/response, they can forge an unhandled exception...

**Risk Factors**:

- CRITICAL severity
- 91.85% exploit probability

**Affected Vendors**: wazuh

**Tags**: `CWE-502`

**References**:

- [https://github.com/wazuh/wazuh/security/advisories/GHSA-hcrc-79hj-m3qh](https://github.com/wazuh/wazuh/security/advisories/GHSA-hcrc-79hj-m3qh)

---

### 66. [CVE-2024-2876](/api/vulns/CVE-2024-2876.json)

**Risk Score**: 63/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 91.3%

**Summary**: The Email Subscribers by Icegram Express – Email Marketing, Newsletters, Automation for WordPress & WooCommerce plugin for WordPress is vulnerable to SQL Injection via the 'run' function of the 'IG_ES_Subscribers_Query' class in all versions up to, and including, 5.7.14 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existin...

**Risk Factors**:

- CRITICAL severity
- 91.35% exploit probability

**Affected Vendors**: icegram

**References**:

- [https://www.wordfence.com/threat-intel/vulnerabilities/id/e0ca6ac4-0d89-4601-94fc-cce5a0af9c56?source=cve](https://www.wordfence.com/threat-intel/vulnerabilities/id/e0ca6ac4-0d89-4601-94fc-cce5a0af9c56?source=cve)
- [https://github.com/WordpressPluginDirectory/email-subscribers/blob/main/email-subscribers/lite/includes/classes/class-ig-es-subscriber-query.php#L304](https://github.com/WordpressPluginDirectory/email-subscribers/blob/main/email-subscribers/lite/includes/classes/class-ig-es-subscriber-query.php#L304)
- [https://github.com/WordpressPluginDirectory/email-subscribers/blob/main/email-subscribers/lite/admin/class-email-subscribers-admin.php#L1433](https://github.com/WordpressPluginDirectory/email-subscribers/blob/main/email-subscribers/lite/admin/class-email-subscribers-admin.php#L1433)

---

### 67. [CVE-2024-9989](/api/vulns/CVE-2024-9989.json)

**Risk Score**: 63/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 91.2%

**Summary**: The Crypto plugin for WordPress is vulnerable to authentication bypass in versions up to, and including, 2.15. This is due a to limited arbitrary method call to 'crypto_connect_ajax_process::log_in' function in the 'crypto_connect_ajax_process' function. This makes it possible for unauthenticated attackers to log in as any existing user on the site, such as an administrator, if they have access to the username.

**Risk Factors**:

- CRITICAL severity
- 91.19% exploit probability

**Affected Vendors**: odude

**Tags**: `CWE-288`

**References**:

- [https://www.wordfence.com/threat-intel/vulnerabilities/id/e21bd924-1d96-4371-972a-5c99d67261cc?source=cve](https://www.wordfence.com/threat-intel/vulnerabilities/id/e21bd924-1d96-4371-972a-5c99d67261cc?source=cve)
- [https://plugins.trac.wordpress.org/browser/crypto/tags/2.10/includes/class-crypto_connect_ajax_register.php#L33](https://plugins.trac.wordpress.org/browser/crypto/tags/2.10/includes/class-crypto_connect_ajax_register.php#L33)
- [https://plugins.trac.wordpress.org/browser/crypto/tags/2.10/includes/class-crypto_connect_ajax_register.php#L138](https://plugins.trac.wordpress.org/browser/crypto/tags/2.10/includes/class-crypto_connect_ajax_register.php#L138)

---

### 68. [CVE-2024-5084](/api/vulns/CVE-2024-5084.json)

**Risk Score**: 63/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 90.8%

**Summary**: The Hash Form – Drag & Drop Form Builder plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'file_upload_action' function in all versions up to, and including, 1.1.0. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

**Risk Factors**:

- CRITICAL severity
- 90.77% exploit probability

**Affected Vendors**: hashthemes

**References**:

- [https://www.wordfence.com/threat-intel/vulnerabilities/id/eef9e2fa-d8f0-42bf-95ac-ee4cafff0b14?source=cve](https://www.wordfence.com/threat-intel/vulnerabilities/id/eef9e2fa-d8f0-42bf-95ac-ee4cafff0b14?source=cve)
- [https://plugins.trac.wordpress.org/browser/hash-form/trunk/admin/classes/HashFormBuilder.php#L764](https://plugins.trac.wordpress.org/browser/hash-form/trunk/admin/classes/HashFormBuilder.php#L764)
- [https://plugins.trac.wordpress.org/changeset/3090341/](https://plugins.trac.wordpress.org/changeset/3090341/)

---

### 69. [CVE-2024-8517](/api/vulns/CVE-2024-8517.json)

**Risk Score**: 63/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 88.8%

**Summary**: SPIP before 4.3.2, 4.2.16, and 
4.1.18 is vulnerable to a command injection issue. A 
remote and unauthenticated attacker can execute arbitrary operating system commands by sending a crafted multipart file upload HTTP request.

**Risk Factors**:

- CRITICAL severity
- 88.84% exploit probability

**Affected Vendors**: spip

**Tags**: `CWE-646`

**References**:

- [https://thinkloveshare.com/hacking/spip_preauth_rce_2024_part_2_a_big_upload/](https://thinkloveshare.com/hacking/spip_preauth_rce_2024_part_2_a_big_upload/)
- [https://blog.spip.net/Mise-a-jour-critique-de-securite-sortie-de-SPIP-4-3-2-SPIP-4-2-16-SPIP-4-1-18.html](https://blog.spip.net/Mise-a-jour-critique-de-securite-sortie-de-SPIP-4-3-2-SPIP-4-2-16-SPIP-4-1-18.html)
- [https://vulncheck.com/advisories/spip-upload-rce](https://vulncheck.com/advisories/spip-upload-rce)

---

### 70. [CVE-2024-51568](/api/vulns/CVE-2024-51568.json)

**Risk Score**: 63/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 88.1%

**Summary**: CyberPanel (aka Cyber Panel) before 2.3.5 allows Command Injection via completePath in the ProcessUtilities.outputExecutioner() sink. There is /filemanager/upload (aka File Manager upload) unauthenticated remote code execution via shell metacharacters.

**Risk Factors**:

- CRITICAL severity
- 88.11% exploit probability

**Affected Vendors**: n/a

**References**:

- [https://cwe.mitre.org/data/definitions/78.html](https://cwe.mitre.org/data/definitions/78.html)
- [https://dreyand.rs/code/review/2024/10/27/what-are-my-options-cyberpanel-v236-pre-auth-rce](https://dreyand.rs/code/review/2024/10/27/what-are-my-options-cyberpanel-v236-pre-auth-rce)
- [https://cyberpanel.net/KnowledgeBase/home/change-logs/](https://cyberpanel.net/KnowledgeBase/home/change-logs/)

---

### 71. [CVE-2024-9707](/api/vulns/CVE-2024-9707.json)

**Risk Score**: 63/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 86.9%

**Summary**: The Hunk Companion plugin for WordPress is vulnerable to unauthorized plugin installation/activation due to a missing capability check on the /wp-json/hc/v1/themehunk-import REST API endpoint in all versions up to, and including, 1.8.4. This makes it possible for unauthenticated attackers to install and activate arbitrary plugins which can be leveraged to achieve remote code execution if another vulnerable plugin is installed and activated.

**Risk Factors**:

- CRITICAL severity
- 86.92% exploit probability

**Affected Vendors**: themehunk

**Tags**: `CWE-862`

**References**:

- [https://www.wordfence.com/threat-intel/vulnerabilities/id/9c101fca-037c-4bed-9dc7-baa021a8b59c?source=cve](https://www.wordfence.com/threat-intel/vulnerabilities/id/9c101fca-037c-4bed-9dc7-baa021a8b59c?source=cve)
- [https://github.com/WordPressBugBounty/plugins-hunk-companion/blob/5a3cedc7b3d35d407b210e691c53c6cb400e4051/hunk-companion/import/app/app.php#L46](https://github.com/WordPressBugBounty/plugins-hunk-companion/blob/5a3cedc7b3d35d407b210e691c53c6cb400e4051/hunk-companion/import/app/app.php#L46)
- [https://wordpress.org/plugins/hunk-companion/](https://wordpress.org/plugins/hunk-companion/)

---

### 72. [CVE-2025-30406](/api/vulns/CVE-2025-30406.json)

**Risk Score**: 63/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.0 | 
**EPSS**: 84.6%

**Summary**: Gladinet CentreStack through 16.1.10296.56315 (fixed in 16.4.10315.56368) has a deserialization vulnerability due to the CentreStack portal's hardcoded machineKey use, as exploited in the wild in March 2025. This enables threat actors (who know the machineKey) to serialize a payload for server-side deserialization to achieve remote code execution. NOTE: a CentreStack admin can manually delete the machineKey defined in portal\web.config.

**Risk Factors**:

- CRITICAL severity
- 84.59% exploit probability

**Affected Vendors**: gladinet

**Tags**: `CWE-321`

**References**:

- [https://www.centrestack.com/p/gce_latest_release.html](https://www.centrestack.com/p/gce_latest_release.html)
- [https://gladinetsupport.s3.us-east-1.amazonaws.com/gladinet/securityadvisory-cve-2005.pdf](https://gladinetsupport.s3.us-east-1.amazonaws.com/gladinet/securityadvisory-cve-2005.pdf)

---

### 73. [CVE-2024-3094](/api/vulns/CVE-2024-3094.json)

**Risk Score**: 63/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 84.0%

**Summary**: Malicious code was discovered in the upstream tarballs of xz, starting with version 5.6.0. 
Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library.

**Risk Factors**:

- CRITICAL severity
- 84.01% exploit probability

**Affected Vendors**: red hat

**Tags**: `CWE-506`

**References**:

- [https://access.redhat.com/security/cve/CVE-2024-3094](https://access.redhat.com/security/cve/CVE-2024-3094)
- [https://bugzilla.redhat.com/show_bug.cgi?id=2272210](https://bugzilla.redhat.com/show_bug.cgi?id=2272210)
- [https://www.openwall.com/lists/oss-security/2024/03/29/4](https://www.openwall.com/lists/oss-security/2024/03/29/4)

---

### 74. [CVE-2025-21293](/api/vulns/CVE-2025-21293.json)

**Risk Score**: 63/100 | 
**Severity**: HIGH | 
**CVSS**: 8.8 | 
**EPSS**: 76.6%

**Summary**: Active Directory Domain Services Elevation of Privilege Vulnerability

**Risk Factors**:

- HIGH severity
- 76.64% exploit probability
- Affects critical infrastructure: microsoft

**Affected Vendors**: microsoft

**Tags**: `CWE-284`

**References**:

- [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-21293](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-21293)

---

### 75. [CVE-2024-6670](/api/vulns/CVE-2024-6670.json)

**Risk Score**: 62/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 94.5%

**Summary**: In WhatsUp Gold versions released before 2024.0.0, a SQL Injection vulnerability allows an unauthenticated attacker to retrieve the users encrypted password.

**Risk Factors**:

- CRITICAL severity
- 94.47% exploit probability

**Affected Vendors**: progress software corporation

**Tags**: `CWE-89`

**References**:

- [https://www.progress.com/network-monitoring](https://www.progress.com/network-monitoring)
- [https://community.progress.com/s/article/WhatsUp-Gold-Security-Bulletin-August-2024](https://community.progress.com/s/article/WhatsUp-Gold-Security-Bulletin-August-2024)

---

### 76. [CVE-2024-7593](/api/vulns/CVE-2024-7593.json)

**Risk Score**: 62/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 94.4%

**Summary**: Incorrect implementation of an authentication algorithm in Ivanti vTM other than versions 22.2R1 or 22.7R2 allows a remote unauthenticated attacker to bypass authentication of the admin panel.

**Risk Factors**:

- CRITICAL severity
- 94.4% exploit probability

**Affected Vendors**: ivanti

**Tags**: `CWE-287`, `CWE-303`

**References**:

- [https://forums.ivanti.com/s/article/Security-Advisory-Ivanti-Virtual-Traffic-Manager-vTM-CVE-2024-7593](https://forums.ivanti.com/s/article/Security-Advisory-Ivanti-Virtual-Traffic-Manager-vTM-CVE-2024-7593)

---

### 77. [CVE-2024-23917](/api/vulns/CVE-2024-23917.json)

**Risk Score**: 62/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 94.4%

**Summary**: In JetBrains TeamCity before 2023.11.3 authentication bypass leading to RCE was possible

**Risk Factors**:

- CRITICAL severity
- 94.38% exploit probability

**Affected Vendors**: jetbrains

**References**:

- [https://www.jetbrains.com/privacy-security/issues-fixed/](https://www.jetbrains.com/privacy-security/issues-fixed/)

---

### 78. [CVE-2024-34102](/api/vulns/CVE-2024-34102.json)

**Risk Score**: 62/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 94.4%

**Summary**: Adobe Commerce versions 2.4.7, 2.4.6-p5, 2.4.5-p7, 2.4.4-p8 and earlier are affected by an Improper Restriction of XML External Entity Reference ('XXE') vulnerability that could result in arbitrary code execution. An attacker could exploit this vulnerability by sending a crafted XML document that references external entities. Exploitation of this issue does not require user interaction.

**Risk Factors**:

- CRITICAL severity
- 94.37% exploit probability

**Affected Vendors**: adobe

**Tags**: `CWE-611`

**References**:

- [https://helpx.adobe.com/security/products/magento/apsb24-40.html](https://helpx.adobe.com/security/products/magento/apsb24-40.html)
- [https://www.vicarius.io/vsociety/posts/cosmicsting-critical-unauthenticated-xxe-vulnerability-in-adobe-commerce-and-magento-cve-2024-34102](https://www.vicarius.io/vsociety/posts/cosmicsting-critical-unauthenticated-xxe-vulnerability-in-adobe-commerce-and-magento-cve-2024-34102)

---

### 79. [CVE-2024-4885](/api/vulns/CVE-2024-4885.json)

**Risk Score**: 62/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 94.3%

**Summary**: In WhatsUp Gold versions released before 2023.1.3, an unauthenticated Remote Code Execution vulnerability in Progress WhatsUpGold.  The 

WhatsUp.ExportUtilities.Export.GetFileWithoutZip



 allows execution of commands with iisapppool\nmconsole privileges.

**Risk Factors**:

- CRITICAL severity
- 94.28% exploit probability

**Affected Vendors**: progress software corporation

**Tags**: `CWE-22`

**References**:

- [https://www.progress.com/network-monitoring](https://www.progress.com/network-monitoring)
- [https://community.progress.com/s/article/WhatsUp-Gold-Security-Bulletin-June-2024](https://community.progress.com/s/article/WhatsUp-Gold-Security-Bulletin-June-2024)

---

### 80. [CVE-2024-4358](/api/vulns/CVE-2024-4358.json)

**Risk Score**: 62/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 94.2%

**Summary**: In Progress Telerik Report Server, version 2024 Q1 (10.0.24.305) or earlier, on IIS, an unauthenticated attacker can gain access to Telerik Report Server restricted functionality via an authentication bypass vulnerability.

**Risk Factors**:

- CRITICAL severity
- 94.25% exploit probability

**Affected Vendors**: progress software corporation

**Tags**: `CWE-290`

**References**:

- [https://docs.telerik.com/report-server/knowledge-base/registration-auth-bypass-cve-2024-4358](https://docs.telerik.com/report-server/knowledge-base/registration-auth-bypass-cve-2024-4358)

---

### 81. [CVE-2024-1512](/api/vulns/CVE-2024-1512.json)

**Risk Score**: 62/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 93.9%

**Summary**: The MasterStudy LMS WordPress Plugin – for Online Courses and Education plugin for WordPress is vulnerable to union based SQL Injection via the 'user' parameter of the /lms/stm-lms/order/items REST route in all versions up to, and including, 3.2.5 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be u...

**Risk Factors**:

- CRITICAL severity
- 93.91% exploit probability

**Affected Vendors**: stylemix

**References**:

- [https://www.wordfence.com/threat-intel/vulnerabilities/id/d6b6d824-51d3-4da9-a39a-b957368df4dc?source=cve](https://www.wordfence.com/threat-intel/vulnerabilities/id/d6b6d824-51d3-4da9-a39a-b957368df4dc?source=cve)
- [https://plugins.trac.wordpress.org/changeset/3036794/masterstudy-lms-learning-management-system/trunk/_core/lms/classes/models/StmStatistics.php](https://plugins.trac.wordpress.org/changeset/3036794/masterstudy-lms-learning-management-system/trunk/_core/lms/classes/models/StmStatistics.php)

---

### 82. [CVE-2024-21412](/api/vulns/CVE-2024-21412.json)

**Risk Score**: 62/100 | 
**Severity**: HIGH | 
**CVSS**: 8.1 | 
**EPSS**: 93.8%

**Summary**: Internet Shortcut Files Security Feature Bypass Vulnerability

**Risk Factors**:

- HIGH severity
- 93.78% exploit probability
- Affects critical infrastructure: microsoft

**Affected Vendors**: microsoft

**Tags**: `CWE-693`

**References**:

- [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21412](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21412)

---

### 83. [CVE-2024-29973](/api/vulns/CVE-2024-29973.json)

**Risk Score**: 62/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 93.7%

**Summary**: ** UNSUPPORTED WHEN ASSIGNED **
The command injection vulnerability in the “setCookie” parameter in Zyxel NAS326 firmware versions before V5.21(AAZF.17)C0 and NAS542 firmware versions before V5.21(ABAG.14)C0 could allow an unauthenticated attacker to execute some operating system (OS) commands by sending a crafted HTTP POST request.

**Risk Factors**:

- CRITICAL severity
- 93.7% exploit probability

**Affected Vendors**: zyxel

**Tags**: `CWE-78`

**References**:

- [https://www.zyxel.com/global/en/support/security-advisories/zyxel-security-advisory-for-multiple-vulnerabilities-in-nas-products-06-04-2024](https://www.zyxel.com/global/en/support/security-advisories/zyxel-security-advisory-for-multiple-vulnerabilities-in-nas-products-06-04-2024)
- [https://outpost24.com/blog/zyxel-nas-critical-vulnerabilities/](https://outpost24.com/blog/zyxel-nas-critical-vulnerabilities/)

---

### 84. [CVE-2024-6782](/api/vulns/CVE-2024-6782.json)

**Risk Score**: 62/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 93.6%

**Summary**: Improper access control in Calibre 6.9.0 ~ 7.14.0 allow unauthenticated attackers to achieve remote code execution.

**Risk Factors**:

- CRITICAL severity
- 93.62% exploit probability

**Affected Vendors**: calibre

**Tags**: `CWE-863`

**References**:

- [https://starlabs.sg/advisories/24/24-6782/](https://starlabs.sg/advisories/24/24-6782/)
- [https://github.com/kovidgoyal/calibre/commit/38a1bf50d8cd22052ae59c513816706c6445d5e9](https://github.com/kovidgoyal/calibre/commit/38a1bf50d8cd22052ae59c513816706c6445d5e9)

---

### 85. [CVE-2024-2879](/api/vulns/CVE-2024-2879.json)

**Risk Score**: 62/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 93.5%

**Summary**: The LayerSlider plugin for WordPress is vulnerable to SQL Injection via the ls_get_popup_markup action in versions 7.9.11 and 7.10.0 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

**Risk Factors**:

- CRITICAL severity
- 93.55% exploit probability

**Affected Vendors**: layerslider

**References**:

- [https://www.wordfence.com/threat-intel/vulnerabilities/id/3fddf96e-029c-4753-ba82-043ca64b78d3?source=cve](https://www.wordfence.com/threat-intel/vulnerabilities/id/3fddf96e-029c-4753-ba82-043ca64b78d3?source=cve)
- [https://layerslider.com/release-log/](https://layerslider.com/release-log/)

---

### 86. [CVE-2024-36412](/api/vulns/CVE-2024-36412.json)

**Risk Score**: 62/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 93.2%

**Summary**: SuiteCRM is an open-source Customer Relationship Management (CRM) software application. Prior to versions 7.14.4 and 8.6.1, a vulnerability in events response entry point allows for a SQL injection attack. Versions 7.14.4 and 8.6.1 contain a fix for this issue.

**Risk Factors**:

- CRITICAL severity
- 93.22% exploit probability

**Affected Vendors**: salesagility

**Tags**: `CWE-89`

**References**:

- [https://github.com/salesagility/SuiteCRM/security/advisories/GHSA-xjx2-38hv-5hh8](https://github.com/salesagility/SuiteCRM/security/advisories/GHSA-xjx2-38hv-5hh8)

---

### 87. [CVE-2024-39914](/api/vulns/CVE-2024-39914.json)

**Risk Score**: 62/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 92.7%

**Summary**: FOG is a cloning/imaging/rescue suite/inventory management system. Prior to 1.5.10.34, packages/web/lib/fog/reportmaker.class.php in FOG was affected by a command injection via the filename parameter to /fog/management/export.php. This vulnerability is fixed in 1.5.10.34.

**Risk Factors**:

- CRITICAL severity
- 92.66% exploit probability

**Affected Vendors**: fogproject

**Tags**: `CWE-77`

**References**:

- [https://github.com/FOGProject/fogproject/security/advisories/GHSA-7h44-6vq6-cq8j](https://github.com/FOGProject/fogproject/security/advisories/GHSA-7h44-6vq6-cq8j)
- [https://github.com/FOGProject/fogproject/commit/2413bc034753c32799785e9bf08164ccd0a2759f](https://github.com/FOGProject/fogproject/commit/2413bc034753c32799785e9bf08164ccd0a2759f)

---

### 88. [CVE-2024-50498](/api/vulns/CVE-2024-50498.json)

**Risk Score**: 62/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 92.6%

**Summary**: Improper Control of Generation of Code ('Code Injection') vulnerability in LUBUS WP Query Console allows Code Injection.This issue affects WP Query Console: from n/a through 1.0.

**Risk Factors**:

- CRITICAL severity
- 92.57% exploit probability

**Affected Vendors**: lubus

**Tags**: `CWE-94`

**References**:

- [https://patchstack.com/database/vulnerability/wp-query-console/wordpress-wp-query-console-plugin-1-0-remote-code-execution-rce-vulnerability?_s_id=cve](https://patchstack.com/database/vulnerability/wp-query-console/wordpress-wp-query-console-plugin-1-0-remote-code-execution-rce-vulnerability?_s_id=cve)

---

### 89. [CVE-2024-9264](/api/vulns/CVE-2024-9264.json)

**Risk Score**: 62/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.9 | 
**EPSS**: 92.3%

**Summary**: The SQL Expressions experimental feature of Grafana allows for the evaluation of `duckdb` queries containing user input. These queries are insufficiently sanitized before being passed to `duckdb`, leading to a command injection and local file inclusion vulnerability. Any user with the VIEWER or higher permission is capable of executing this attack.  The `duckdb` binary must be present in Grafana's $PATH for this attack to function; by default, this binary is not installed in Grafana distribution...

**Risk Factors**:

- CRITICAL severity
- 92.34% exploit probability

**Affected Vendors**: grafana

**Tags**: `CWE-94`

**References**:

- [https://grafana.com/security/security-advisories/cve-2024-9264/](https://grafana.com/security/security-advisories/cve-2024-9264/)

---

### 90. [CVE-2024-9014](/api/vulns/CVE-2024-9014.json)

**Risk Score**: 62/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.9 | 
**EPSS**: 92.3%

**Summary**: pgAdmin versions 8.11 and earlier are vulnerable to a security flaw in OAuth2 authentication. This vulnerability allows an attacker to potentially obtain the client ID and secret, leading to unauthorized access to user data.

**Risk Factors**:

- CRITICAL severity
- 92.32% exploit probability

**Affected Vendors**: pgadmin.org

**References**:

- [https://github.com/pgadmin-org/pgadmin4/issues/7945](https://github.com/pgadmin-org/pgadmin4/issues/7945)

---

### 91. [CVE-2024-9047](/api/vulns/CVE-2024-9047.json)

**Risk Score**: 62/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 92.1%

**Summary**: The WordPress File Upload plugin for WordPress is vulnerable to Path Traversal in all versions up to, and including, 4.24.11 via wfu_file_downloader.php. This makes it possible for unauthenticated attackers to read or delete files outside of the originally intended directory. Successful exploitation requires the targeted WordPress installation to be using PHP 7.4 or earlier.

**Risk Factors**:

- CRITICAL severity
- 92.1% exploit probability

**Affected Vendors**: nickboss

**Tags**: `CWE-22`

**References**:

- [https://www.wordfence.com/threat-intel/vulnerabilities/id/554a314c-9e8e-4691-9792-d086790ef40f?source=cve](https://www.wordfence.com/threat-intel/vulnerabilities/id/554a314c-9e8e-4691-9792-d086790ef40f?source=cve)
- [https://plugins.trac.wordpress.org/changeset/3164449/wp-file-upload](https://plugins.trac.wordpress.org/changeset/3164449/wp-file-upload)

---

### 92. [CVE-2024-44000](/api/vulns/CVE-2024-44000.json)

**Risk Score**: 62/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 92.0%

**Summary**: Insufficiently Protected Credentials vulnerability in LiteSpeed Technologies LiteSpeed Cache allows Authentication Bypass.This issue affects LiteSpeed Cache: from n/a before 6.5.0.1.

**Risk Factors**:

- CRITICAL severity
- 92.01% exploit probability

**Affected Vendors**: litespeed technologies

**Tags**: `CWE-522`

**References**:

- [https://patchstack.com/database/vulnerability/litespeed-cache/wordpress-litespeed-cache-plugin-6-5-0-1-unauthenticated-account-takeover-vulnerability?_s_id=cve](https://patchstack.com/database/vulnerability/litespeed-cache/wordpress-litespeed-cache-plugin-6-5-0-1-unauthenticated-account-takeover-vulnerability?_s_id=cve)
- [https://patchstack.com/articles/critical-account-takeover-vulnerability-patched-in-litespeed-cache-plugin?_s_id=cve](https://patchstack.com/articles/critical-account-takeover-vulnerability-patched-in-litespeed-cache-plugin?_s_id=cve)

---

### 93. [CVE-2024-29972](/api/vulns/CVE-2024-29972.json)

**Risk Score**: 62/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 91.5%

**Summary**: ** UNSUPPORTED WHEN ASSIGNED **
The command injection vulnerability in the CGI program "remote_help-cgi" in Zyxel NAS326 firmware versions before V5.21(AAZF.17)C0 and NAS542 firmware versions before V5.21(ABAG.14)C0 could allow an unauthenticated attacker to execute some operating system (OS) commands by sending a crafted HTTP POST request.

**Risk Factors**:

- CRITICAL severity
- 91.53% exploit probability

**Affected Vendors**: zyxel

**Tags**: `CWE-78`

**References**:

- [https://www.zyxel.com/global/en/support/security-advisories/zyxel-security-advisory-for-multiple-vulnerabilities-in-nas-products-06-04-2024](https://www.zyxel.com/global/en/support/security-advisories/zyxel-security-advisory-for-multiple-vulnerabilities-in-nas-products-06-04-2024)
- [https://outpost24.com/blog/zyxel-nas-critical-vulnerabilities/](https://outpost24.com/blog/zyxel-nas-critical-vulnerabilities/)

---

### 94. [CVE-2024-48914](/api/vulns/CVE-2024-48914.json)

**Risk Score**: 62/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.1 | 
**EPSS**: 90.9%

**Summary**: Vendure is an open-source headless commerce platform. Prior to versions 3.0.5 and 2.3.3, a vulnerability in Vendure's asset server plugin allows an attacker to craft a request which is able to traverse the server file system and retrieve the contents of arbitrary files, including sensitive data such as configuration files, environment variables, and other critical data stored on the server. In the same code path is an additional vector for crashing the server via a malformed URI. Patches are ava...

**Risk Factors**:

- CRITICAL severity
- 90.93% exploit probability

**Affected Vendors**: vendure-ecommerce

**Tags**: `CWE-22`, `CWE-20`

**References**:

- [https://github.com/vendure-ecommerce/vendure/security/advisories/GHSA-r9mq-3c9r-fmjq](https://github.com/vendure-ecommerce/vendure/security/advisories/GHSA-r9mq-3c9r-fmjq)
- [https://github.com/vendure-ecommerce/vendure/commit/e2ee0c43159b3d13b51b78654481094fdd4850c5](https://github.com/vendure-ecommerce/vendure/commit/e2ee0c43159b3d13b51b78654481094fdd4850c5)
- [https://github.com/vendure-ecommerce/vendure/commit/e4b58af6822d38a9c92a1d8573e19288b8edaa1c](https://github.com/vendure-ecommerce/vendure/commit/e4b58af6822d38a9c92a1d8573e19288b8edaa1c)

---

### 95. [CVE-2024-3922](/api/vulns/CVE-2024-3922.json)

**Risk Score**: 62/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 89.7%

**Summary**: The Dokan Pro plugin for WordPress is vulnerable to SQL Injection via the 'code' parameter in all versions up to, and including, 3.10.3 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

**Risk Factors**:

- CRITICAL severity
- 89.67% exploit probability

**Affected Vendors**: wedevs

**References**:

- [https://www.wordfence.com/threat-intel/vulnerabilities/id/d9de41de-f2f7-4b16-8ec9-d30bbd3d8786?source=cve](https://www.wordfence.com/threat-intel/vulnerabilities/id/d9de41de-f2f7-4b16-8ec9-d30bbd3d8786?source=cve)
- [https://dokan.co/docs/wordpress/changelog/](https://dokan.co/docs/wordpress/changelog/)

---

### 96. [CVE-2024-22319](/api/vulns/CVE-2024-22319.json)

**Risk Score**: 62/100 | 
**Severity**: HIGH | 
**CVSS**: 8.1 | 
**EPSS**: 89.4%

**Summary**: 


IBM Operational Decision Manager 8.10.3, 8.10.4, 8.10.5.1, 8.11, 8.11.0.1, 8.11.1 and 8.12.0.1 is susceptible to remote code execution attack via JNDI injection when passing an unchecked argument to a certain API. IBM X-Force ID: 279145.





**Risk Factors**:

- HIGH severity
- 89.36% exploit probability
- Affects critical infrastructure: ibm

**Affected Vendors**: ibm

**Tags**: `CWE-74`

**References**:

- [https://www.ibm.com/support/pages/node/7112382](https://www.ibm.com/support/pages/node/7112382)
- [https://exchange.xforce.ibmcloud.com/vulnerabilities/279145](https://exchange.xforce.ibmcloud.com/vulnerabilities/279145)

---

### 97. [CVE-2024-5276](/api/vulns/CVE-2024-5276.json)

**Risk Score**: 62/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 87.3%

**Summary**: A SQL Injection vulnerability in Fortra FileCatalyst Workflow allows an attacker to modify application data.  Likely impacts include creation of administrative users and deletion or modification of data in the application database. Data exfiltration via SQL injection is not possible using this vulnerability. Successful unauthenticated exploitation requires a Workflow system with anonymous access enabled, otherwise an authenticated user is required. This issue affects all versions of FileCatalyst...

**Risk Factors**:

- CRITICAL severity
- 87.34% exploit probability

**Affected Vendors**: fortra

**Tags**: `CWE-20`, `CWE-89`

**References**:

- [https://support.fortra.com/filecatalyst/kb-articles/advisory-6-24-2024-filecatalyst-workflow-sql-injection-vulnerability-YmYwYWY4OTYtNTUzMi1lZjExLTg0MGEtNjA0NWJkMDg3MDA0](https://support.fortra.com/filecatalyst/kb-articles/advisory-6-24-2024-filecatalyst-workflow-sql-injection-vulnerability-YmYwYWY4OTYtNTUzMi1lZjExLTg0MGEtNjA0NWJkMDg3MDA0)
- [https://www.fortra.com/security/advisory/fi-2024-008](https://www.fortra.com/security/advisory/fi-2024-008)
- [https://www.tenable.com/security/research/tra-2024-25](https://www.tenable.com/security/research/tra-2024-25)

---

### 98. [CVE-2024-48766](/api/vulns/CVE-2024-48766.json)

**Risk Score**: 62/100 | 
**Severity**: HIGH | 
**CVSS**: 8.6 | 
**EPSS**: 84.6%

**Summary**: NetAlertX 24.7.18 before 24.10.12 allows unauthenticated file reading because an HTTP client can ignore a redirect, and because of factors related to strpos and directory traversal, as exploited in the wild in May 2025. This is related to components/logs.php.

**Risk Factors**:

- HIGH severity
- 84.6% exploit probability

**Affected Vendors**: netalertx

**Tags**: `CWE-698`

**References**:

- [https://rhinosecuritylabs.com/research/cve-2024-46506-rce-in-netalertx/](https://rhinosecuritylabs.com/research/cve-2024-46506-rce-in-netalertx/)
- [https://raw.githubusercontent.com/rapid7/metasploit-framework/master/modules/auxiliary/scanner/http/netalertx_file_read.rb](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/modules/auxiliary/scanner/http/netalertx_file_read.rb)

---

### 99. [CVE-2024-28253](/api/vulns/CVE-2024-28253.json)

**Risk Score**: 62/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.4 | 
**EPSS**: 83.7%

**Summary**: OpenMetadata is a unified platform for discovery, observability, and governance powered by a central metadata repository, in-depth lineage, and seamless team collaboration. `CompiledRule::validateExpression` is also called from `PolicyRepository.prepare`. `prepare()` is called from `EntityRepository.prepareInternal()` which, in turn, gets called from `EntityResource.createOrUpdate()`. Note that even though there is an authorization check (`authorizer.authorize()`), it gets called after `prepareI...

**Risk Factors**:

- CRITICAL severity
- 83.68% exploit probability

**Affected Vendors**: open-metadata

**Tags**: `CWE-94`

**References**:

- [https://github.com/open-metadata/OpenMetadata/security/advisories/GHSA-7vf4-x5m2-r6gr](https://github.com/open-metadata/OpenMetadata/security/advisories/GHSA-7vf4-x5m2-r6gr)
- [https://codeql.github.com/codeql-query-help/java/java-spel-expression-injection](https://codeql.github.com/codeql-query-help/java/java-spel-expression-injection)
- [https://github.com/open-metadata/OpenMetadata/blob/b6b337e09a05101506a5faba4b45d370cc3c9fc8/openmetadata-service/src/main/java/org/openmetadata/service/jdbi3/EntityRepository.java#L693](https://github.com/open-metadata/OpenMetadata/blob/b6b337e09a05101506a5faba4b45d370cc3c9fc8/openmetadata-service/src/main/java/org/openmetadata/service/jdbi3/EntityRepository.java#L693)

---

### 100. [CVE-2025-1094](/api/vulns/CVE-2025-1094.json)

**Risk Score**: 62/100 | 
**Severity**: HIGH | 
**CVSS**: 8.1 | 
**EPSS**: 83.6%

**Summary**: Improper neutralization of quoting syntax in PostgreSQL libpq functions PQescapeLiteral(), PQescapeIdentifier(), PQescapeString(), and PQescapeStringConn() allows a database input provider to achieve SQL injection in certain usage patterns.  Specifically, SQL injection requires the application to use the function result to construct input to psql, the PostgreSQL interactive terminal.  Similarly, improper neutralization of quoting syntax in PostgreSQL command line utility programs allows a source...

**Risk Factors**:

- HIGH severity
- 83.63% exploit probability

**Affected Vendors**: n/a

**Tags**: `CWE-149`

**References**:

- [https://www.postgresql.org/support/security/CVE-2025-1094/](https://www.postgresql.org/support/security/CVE-2025-1094/)

---

## Data Sources

This briefing was generated from the following sources:


---

*This briefing was automatically generated. For the complete dataset, visit the [vulnerability dashboard](/).*