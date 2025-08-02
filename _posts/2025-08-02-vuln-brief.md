---
title: Morning Vulnerability Briefing - 2025-08-02
date: 2025-08-02T05:14:56.702832
layout: layouts/post.njk
tags: [vulnerability, briefing, security]
vulnerabilityCount: 30
criticalCount: 0
highCount: 1
---

# Morning Vulnerability Briefing - 2025-08-02

Today's briefing covers **30 vulnerabilities** from 0 sources.

## Risk Distribution

- 🔴 **Critical Risk**: 0 vulnerabilities
- 🟠 **High Risk**: 1 vulnerabilities
- 🟡 **Medium Risk**: 29 vulnerabilities
- 🟢 **Low Risk**: 0 vulnerabilities

## Top Vulnerabilities

### 1. [CVE-2025-47812](/api/vulns/CVE-2025-47812.json)

**Risk Score**: 70/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 91.0%

**Summary**: In Wing FTP Server before 7.4.4. the user and admin web interfaces mishandle '\0' bytes, ultimately allowing injection of arbitrary Lua code into user session files. This can be used to execute arbitrary system commands with the privileges of the FTP service (root or SYSTEM by default). This is thus a remote code execution vulnerability that guarantees a total server compromise. This is also exploitable via anonymous FTP accounts.

**Risk Factors**:

- CRITICAL severity
- 90.99% exploit probability
- Published within last month

**Affected Vendors**: Ftp, Total, Wftpserver

**Tags**: `CWE-158`

**References**:

- [https://www.wftpserver.com](https://www.wftpserver.com)
- [https://www.rcesecurity.com/2025/06/what-the-null-wing-ftp-server-rce-cve-2025-47812/](https://www.rcesecurity.com/2025/06/what-the-null-wing-ftp-server-rce-cve-2025-47812/)

---

### 2. [CVE-2025-49113](/api/vulns/CVE-2025-49113.json)

**Risk Score**: 69/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.9 | 
**EPSS**: 88.1%

**Summary**: Roundcube Webmail before 1.5.10 and 1.6.x before 1.6.11 allows remote code execution by authenticated users because the _from parameter in a URL is not validated in program/actions/settings/upload.php, leading to PHP Object Deserialization.

**Risk Factors**:

- CRITICAL severity
- 88.14% exploit probability

**Affected Vendors**: Roundcube

**Tags**: `CWE-502`

**References**:

- [https://roundcube.net/news/2025/06/01/security-updates-1.6.11-and-1.5.10](https://roundcube.net/news/2025/06/01/security-updates-1.6.11-and-1.5.10)
- [https://github.com/roundcube/roundcubemail/pull/9865](https://github.com/roundcube/roundcubemail/pull/9865)
- [https://github.com/roundcube/roundcubemail/releases/tag/1.6.11](https://github.com/roundcube/roundcubemail/releases/tag/1.6.11)

---

### 3. [CVE-2025-1974](/api/vulns/CVE-2025-1974.json)

**Risk Score**: 68/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 87.8%

**Summary**: A security issue was discovered in Kubernetes where under certain conditions, an unauthenticated attacker with access to the pod network can achieve arbitrary code execution in the context of the ingress-nginx controller. This can lead to disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)

**Risk Factors**:

- CRITICAL severity
- 87.81% exploit probability
- Affects critical infrastructure: kubernetes

**Affected Vendors**: Kubernetes

**Tags**: `CWE-653`

**References**:

- [https://https://github.com/kubernetes/kubernetes/issues/131009](https://https://github.com/kubernetes/kubernetes/issues/131009)

---

### 4. [CVE-2025-24893](/api/vulns/CVE-2025-24893.json)

**Risk Score**: 67/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 93.3%

**Summary**: XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `<host>/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20se...

**Risk Factors**:

- CRITICAL severity
- 93.31% exploit probability

**Affected Vendors**: Xwiki

**Tags**: `CWE-95`

**References**:

- [https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-rr6p-3pfg-562j](https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-rr6p-3pfg-562j)
- [https://github.com/xwiki/xwiki-platform/commit/67021db9b8ed26c2236a653269302a86bf01ef40](https://github.com/xwiki/xwiki-platform/commit/67021db9b8ed26c2236a653269302a86bf01ef40)
- [https://github.com/xwiki/xwiki-platform/blob/568447cad5172d97d6bbcfda9f6183689c2cf086/xwiki-platform-core/xwiki-platform-search/xwiki-platform-search-solr/xwiki-platform-search-solr-ui/src/main/resources/Main/SolrSearchMacros.xml#L955](https://github.com/xwiki/xwiki-platform/blob/568447cad5172d97d6bbcfda9f6183689c2cf086/xwiki-platform-core/xwiki-platform-search/xwiki-platform-search-solr/xwiki-platform-search-solr-ui/src/main/resources/Main/SolrSearchMacros.xml#L955)

---

### 5. [CVE-2025-47916](/api/vulns/CVE-2025-47916.json)

**Risk Score**: 67/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 90.2%

**Summary**: Invision Community 5.0.0 before 5.0.7 allows remote code execution via crafted template strings to themeeditor.php. The issue lies within the themeeditor controller (file: /applications/core/modules/front/system/themeeditor.php), where a protected method named customCss can be invoked by unauthenticated users. This method passes the value of the content parameter to the Theme::makeProcessFunction() method; hence it is evaluated by the template engine. Accordingly, this can be exploited by unauth...

**Risk Factors**:

- CRITICAL severity
- 90.16% exploit probability

**Affected Vendors**: Invisioncommunity, Template

**Tags**: `CWE-1336`

**References**:

- [https://invisioncommunity.com/release-notes-v5/507-r41/](https://invisioncommunity.com/release-notes-v5/507-r41/)
- [https://karmainsecurity.com/KIS-2025-02](https://karmainsecurity.com/KIS-2025-02)

---

### 6. [CVE-2025-1661](/api/vulns/CVE-2025-1661.json)

**Risk Score**: 67/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 87.4%

**Summary**: The HUSKY – Products Filter Professional for WooCommerce plugin for WordPress is vulnerable to Local File Inclusion in all versions up to, and including, 1.3.6.5 via the 'template' parameter of the woof_text_search AJAX action. This makes it possible for unauthenticated attackers to include and execute arbitrary files on the server, allowing the execution of any PHP code in those files. This can be used to bypass access controls, obtain sensitive data, or achieve code execution in cases where im...

**Risk Factors**:

- CRITICAL severity
- 87.38% exploit probability

**Affected Vendors**: Realmag777, The, WordPress

**Tags**: `CWE-22`

**References**:

- [https://www.wordfence.com/threat-intel/vulnerabilities/id/9ae7b6fc-2120-4573-8b1b-d5422d435fa5?source=cve](https://www.wordfence.com/threat-intel/vulnerabilities/id/9ae7b6fc-2120-4573-8b1b-d5422d435fa5?source=cve)
- [https://plugins.trac.wordpress.org/browser/woocommerce-products-filter/trunk/ext/by_text/index.php](https://plugins.trac.wordpress.org/browser/woocommerce-products-filter/trunk/ext/by_text/index.php)
- [https://plugins.trac.wordpress.org/changeset?sfp_email=&sfph_mail=&reponame=&old=3253169%40woocommerce-products-filter&new=3253169%40woocommerce-products-filter&sfp_email=&sfph_mail=](https://plugins.trac.wordpress.org/changeset?sfp_email=&sfph_mail=&reponame=&old=3253169%40woocommerce-products-filter&new=3253169%40woocommerce-products-filter&sfp_email=&sfph_mail=)

---

### 7. [CVE-2025-29927](/api/vulns/CVE-2025-29927.json)

**Risk Score**: 66/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.1 | 
**EPSS**: 93.6%

**Summary**: Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed ...

**Risk Factors**:

- CRITICAL severity
- 93.63% exploit probability

**Affected Vendors**: React, Vercel

**Tags**: `CWE-285`

**References**:

- [https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw](https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw)
- [https://github.com/vercel/next.js/commit/52a078da3884efe6501613c7834a3d02a91676d2](https://github.com/vercel/next.js/commit/52a078da3884efe6501613c7834a3d02a91676d2)
- [https://github.com/vercel/next.js/commit/5fd3ae8f8542677c6294f32d18022731eab6fe48](https://github.com/vercel/next.js/commit/5fd3ae8f8542677c6294f32d18022731eab6fe48)

---

### 8. [CVE-2025-3248](/api/vulns/CVE-2025-3248.json)

**Risk Score**: 65/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 92.2%

**Summary**: Langflow versions prior to 1.3.0 are susceptible to code injection in 
the /api/v1/validate/code endpoint. A remote and unauthenticated attacker can send crafted HTTP requests to execute arbitrary
code.

**Risk Factors**:

- CRITICAL severity
- 92.15% exploit probability

**Affected Vendors**: Langflow-ai

**Tags**: `CWE-306`

**References**:

- [https://github.com/langflow-ai/langflow/pull/6911](https://github.com/langflow-ai/langflow/pull/6911)
- [https://github.com/langflow-ai/langflow/releases/tag/1.3.0](https://github.com/langflow-ai/langflow/releases/tag/1.3.0)
- [https://www.horizon3.ai/attack-research/disclosures/unsafe-at-any-speed-abusing-python-exec-for-unauth-rce-in-langflow-ai/](https://www.horizon3.ai/attack-research/disclosures/unsafe-at-any-speed-abusing-python-exec-for-unauth-rce-in-langflow-ai/)

---

### 9. [CVE-2025-31161](/api/vulns/CVE-2025-31161.json)

**Risk Score**: 64/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 83.3%

**Summary**: CrushFTP 10 before 10.8.4 and 11 before 11.3.1 allows authentication bypass and takeover of the crushadmin account (unless a DMZ proxy instance is used), as exploited in the wild in March and April 2025, aka "Unauthenticated HTTP(S) port access." A race condition exists in the AWS4-HMAC (compatible with S3) authorization method of the HTTP component of the FTP server. The server first verifies the existence of the user by performing a call to login_user_pass() with no password requirement. This ...

**Risk Factors**:

- CRITICAL severity
- 83.27% exploit probability

**Affected Vendors**: Crushftp, Ftp, The

**Tags**: `CWE-305`

**References**:

- [https://outpost24.com/blog/crushftp-auth-bypass-vulnerability/](https://outpost24.com/blog/crushftp-auth-bypass-vulnerability/)
- [https://crushftp.com/crush11wiki/Wiki.jsp?page=Update#section-Update-VulnerabilityInfo](https://crushftp.com/crush11wiki/Wiki.jsp?page=Update#section-Update-VulnerabilityInfo)

---

### 10. [CVE-2025-32432](/api/vulns/CVE-2025-32432.json)

**Risk Score**: 64/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 77.6%

**Summary**: Craft is a flexible, user-friendly CMS for creating custom digital experiences on the web and beyond. Starting from version 3.0.0-RC1 to before 3.9.15, 4.0.0-RC1 to before 4.14.15, and 5.0.0-RC1 to before 5.6.17, Craft is vulnerable to remote code execution. This is a high-impact, low-complexity attack vector. This issue has been patched in versions 3.9.15, 4.14.15, and 5.6.17, and is an additional fix for CVE-2023-41892.

**Risk Factors**:

- CRITICAL severity
- 77.59% exploit probability

**Affected Vendors**: Craftcms

**Tags**: `CWE-94`

**References**:

- [https://github.com/craftcms/cms/security/advisories/GHSA-f3gw-9ww9-jmc3](https://github.com/craftcms/cms/security/advisories/GHSA-f3gw-9ww9-jmc3)
- [https://github.com/craftcms/cms/commit/e1c85441fa47eeb7c688c2053f25419bc0547b47](https://github.com/craftcms/cms/commit/e1c85441fa47eeb7c688c2053f25419bc0547b47)
- [https://github.com/craftcms/cms/blob/3.x/CHANGELOG.md#3915---2025-04-10-critical](https://github.com/craftcms/cms/blob/3.x/CHANGELOG.md#3915---2025-04-10-critical)

---

### 11. [CVE-2025-48827](/api/vulns/CVE-2025-48827.json)

**Risk Score**: 64/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 73.4%

**Summary**: vBulletin 5.0.0 through 5.7.5 and 6.0.0 through 6.0.3 allows unauthenticated users to invoke protected API controllers' methods when running on PHP 8.1 or later, as demonstrated by the /api.php?method=protectedMethod pattern, as exploited in the wild in May 2025.

**Risk Factors**:

- CRITICAL severity
- 73.44% exploit probability

**Affected Vendors**: PHP, Vbulletin

**Tags**: `CWE-424`

**References**:

- [https://karmainsecurity.com/dont-call-that-protected-method-vbulletin-rce](https://karmainsecurity.com/dont-call-that-protected-method-vbulletin-rce)
- [https://kevintel.com/CVE-2025-48827](https://kevintel.com/CVE-2025-48827)

---

### 12. [CVE-2025-24016](/api/vulns/CVE-2025-24016.json)

**Risk Score**: 63/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.9 | 
**EPSS**: 91.7%

**Summary**: Wazuh is a free and open source platform used for threat prevention, detection, and response. Starting in version 4.4.0 and prior to version 4.9.1, an unsafe deserialization vulnerability allows for remote code execution on Wazuh servers. DistributedAPI parameters are a serialized as JSON and deserialized using `as_wazuh_object` (in `framework/wazuh/core/cluster/common.py`). If an attacker manages to inject an unsanitized dictionary in DAPI request/response, they can forge an unhandled exception...

**Risk Factors**:

- CRITICAL severity
- 91.65% exploit probability

**Affected Vendors**: Wazuh

**Tags**: `CWE-502`

**References**:

- [https://github.com/wazuh/wazuh/security/advisories/GHSA-hcrc-79hj-m3qh](https://github.com/wazuh/wazuh/security/advisories/GHSA-hcrc-79hj-m3qh)

---

### 13. [CVE-2025-30066](/api/vulns/CVE-2025-30066.json)

**Risk Score**: 62/100 | 
**Severity**: HIGH | 
**CVSS**: 8.6 | 
**EPSS**: 81.7%

**Summary**: tj-actions changed-files before 46 allows remote attackers to discover secrets by reading actions logs. (The tags v1 through v45.0.7 were affected on 2025-03-14 and 2025-03-15 because they were modified by a threat actor to point at commit 0e58ed8, which contained malicious updateFeatures code.)

**Risk Factors**:

- HIGH severity
- 81.68% exploit probability

**Affected Vendors**: Tj-actions

**Tags**: `CWE-506`

**References**:

- [https://github.com/github/docs/blob/962a1c8dccb8c0f66548b324e5b921b5e4fbc3d6/content/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions.md?plain=1#L191-L193](https://github.com/github/docs/blob/962a1c8dccb8c0f66548b324e5b921b5e4fbc3d6/content/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions.md?plain=1#L191-L193)
- [https://github.com/tj-actions/changed-files/issues/2463](https://github.com/tj-actions/changed-files/issues/2463)
- [https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files-action-is-compromised](https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files-action-is-compromised)

---

### 14. [CVE-2025-27007](/api/vulns/CVE-2025-27007.json)

**Risk Score**: 62/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 78.6%

**Summary**: Incorrect Privilege Assignment vulnerability in Brainstorm Force SureTriggers allows Privilege Escalation.This issue affects SureTriggers: from n/a through 1.0.82.

**Risk Factors**:

- CRITICAL severity
- 78.6% exploit probability

**Affected Vendors**: Brainstorm Force, WordPress

**Tags**: `CWE-266`

**References**:

- [https://patchstack.com/database/wordpress/plugin/suretriggers/vulnerability/wordpress-suretriggers-1-0-82-privilege-escalation-vulnerability?_s_id=cve](https://patchstack.com/database/wordpress/plugin/suretriggers/vulnerability/wordpress-suretriggers-1-0-82-privilege-escalation-vulnerability?_s_id=cve)
- [https://patchstack.com/articles/additional-critical-ottokit-formerly-suretriggers-vulnerability-patched?_s_id=cve](https://patchstack.com/articles/additional-critical-ottokit-formerly-suretriggers-vulnerability-patched?_s_id=cve)

---

### 15. [CVE-2025-21298](/api/vulns/CVE-2025-21298.json)

**Risk Score**: 62/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 70.6%

**Summary**: Windows OLE Remote Code Execution Vulnerability

**Risk Factors**:

- CRITICAL severity
- 70.56% exploit probability
- Affects critical infrastructure: microsoft

**Affected Vendors**: Microsoft

**Tags**: `CWE-416`

**References**:

- [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-21298](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-21298)

---

### 16. [CVE-2025-32433](/api/vulns/CVE-2025-32433.json)

**Risk Score**: 62/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 67.4%

**Summary**: Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary w...

**Risk Factors**:

- CRITICAL severity
- 67.37% exploit probability

**Affected Vendors**: Erlang, Ssh

**Tags**: `CWE-306`

**References**:

- [https://github.com/erlang/otp/security/advisories/GHSA-37cp-fgq5-7wc2](https://github.com/erlang/otp/security/advisories/GHSA-37cp-fgq5-7wc2)
- [https://github.com/erlang/otp/commit/0fcd9c56524b28615e8ece65fc0c3f66ef6e4c12](https://github.com/erlang/otp/commit/0fcd9c56524b28615e8ece65fc0c3f66ef6e4c12)
- [https://github.com/erlang/otp/commit/6eef04130afc8b0ccb63c9a0d8650209cf54892f](https://github.com/erlang/otp/commit/6eef04130afc8b0ccb63c9a0d8650209cf54892f)

---

### 17. [CVE-2025-30406](/api/vulns/CVE-2025-30406.json)

**Risk Score**: 61/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.0 | 
**EPSS**: 83.5%

**Summary**: Gladinet CentreStack through 16.1.10296.56315 (fixed in 16.4.10315.56368) has a deserialization vulnerability due to the CentreStack portal's hardcoded machineKey use, as exploited in the wild in March 2025. This enables threat actors (who know the machineKey) to serialize a payload for server-side deserialization to achieve remote code execution. NOTE: a CentreStack admin can manually delete the machineKey defined in portal\web.config.

**Risk Factors**:

- CRITICAL severity
- 83.46% exploit probability

**Affected Vendors**: For, Gladinet

**Tags**: `CWE-321`

**References**:

- [https://www.centrestack.com/p/gce_latest_release.html](https://www.centrestack.com/p/gce_latest_release.html)
- [https://gladinetsupport.s3.us-east-1.amazonaws.com/gladinet/securityadvisory-cve-2005.pdf](https://gladinetsupport.s3.us-east-1.amazonaws.com/gladinet/securityadvisory-cve-2005.pdf)

---

### 18. [CVE-2025-1316](/api/vulns/CVE-2025-1316.json)

**Risk Score**: 61/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 83.0%

**Summary**: Edimax IC-7100 does not properly neutralize requests. An attacker can create specially crafted requests to achieve remote code execution on the device

**Risk Factors**:

- CRITICAL severity
- 83.0% exploit probability

**Affected Vendors**: Edimax

**Tags**: `CWE-78`

**References**:

- [https://www.cisa.gov/news-events/ics-advisories/icsa-25-063-08](https://www.cisa.gov/news-events/ics-advisories/icsa-25-063-08)

---

### 19. [CVE-2025-1094](/api/vulns/CVE-2025-1094.json)

**Risk Score**: 61/100 | 
**Severity**: HIGH | 
**CVSS**: 8.1 | 
**EPSS**: 79.5%

**Summary**: Improper neutralization of quoting syntax in PostgreSQL libpq functions PQescapeLiteral(), PQescapeIdentifier(), PQescapeString(), and PQescapeStringConn() allows a database input provider to achieve SQL injection in certain usage patterns.  Specifically, SQL injection requires the application to use the function result to construct input to psql, the PostgreSQL interactive terminal.  Similarly, improper neutralization of quoting syntax in PostgreSQL command line utility programs allows a source...

**Risk Factors**:

- HIGH severity
- 79.48% exploit probability

**Affected Vendors**: N/a, PostgreSQL

**Tags**: `CWE-149`

**References**:

- [https://www.postgresql.org/support/security/CVE-2025-1094/](https://www.postgresql.org/support/security/CVE-2025-1094/)

---

### 20. [CVE-2025-34028](/api/vulns/CVE-2025-34028.json)

**Risk Score**: 61/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 64.7%

**Summary**: The Commvault Command Center Innovation Release allows an unauthenticated actor to upload ZIP files that represent install packages that, when expanded by the target server, are vulnerable to path traversal vulnerability that can result in Remote Code Execution via malicious JSP.





This issue affects Command Center Innovation Release: 11.38.0 to 11.38.20. The vulnerability is fixed in 11.38.20 with SP38-CU20-433 and SP38-CU20-436 and also fixed in 11.38.25 with SP38-CU25-434 and SP38-CU25-438...

**Risk Factors**:

- CRITICAL severity
- 64.66% exploit probability

**Affected Vendors**: Commvault, Target

**Tags**: `CWE-22`, `CWE-306`

**References**:

- [https://documentation.commvault.com/securityadvisories/CV_2025_04_1.html](https://documentation.commvault.com/securityadvisories/CV_2025_04_1.html)
- [https://labs.watchtowr.com/fire-in-the-hole-were-breaching-the-vault-commvault-remote-code-execution-cve-2025-34028/](https://labs.watchtowr.com/fire-in-the-hole-were-breaching-the-vault-commvault-remote-code-execution-cve-2025-34028/)
- [https://github.com/watchtowrlabs/watchTowr-vs-Commvault-PreAuth-RCE-CVE-2025-34028](https://github.com/watchtowrlabs/watchTowr-vs-Commvault-PreAuth-RCE-CVE-2025-34028)

---

### 21. [CVE-2025-3102](/api/vulns/CVE-2025-3102.json)

**Risk Score**: 60/100 | 
**Severity**: HIGH | 
**CVSS**: 8.1 | 
**EPSS**: 86.0%

**Summary**: The SureTriggers: All-in-One Automation Platform plugin for WordPress is vulnerable to an authentication bypass leading to administrative account creation due to a missing empty value check on the 'secret_key' value in the 'autheticate_user' function in all versions up to, and including, 1.0.78. This makes it possible for unauthenticated attackers to create administrator accounts on the target website when the plugin is installed and activated but not configured with an API key.

**Risk Factors**:

- HIGH severity
- 85.99% exploit probability

**Affected Vendors**: Brainstormforce, WordPress

**Tags**: `CWE-697`

**References**:

- [https://www.wordfence.com/threat-intel/vulnerabilities/id/ec017311-f150-4a14-a4b4-b5634f574e2b?source=cve](https://www.wordfence.com/threat-intel/vulnerabilities/id/ec017311-f150-4a14-a4b4-b5634f574e2b?source=cve)
- [https://plugins.trac.wordpress.org/browser/suretriggers/trunk/src/Controllers/RestController.php#L59](https://plugins.trac.wordpress.org/browser/suretriggers/trunk/src/Controllers/RestController.php#L59)
- [https://plugins.trac.wordpress.org/changeset?sfp_email=&sfph_mail=&reponame=&new=3266499%40suretriggers%2Ftrunk&old=3264905%40suretriggers%2Ftrunk&sfp_email=&sfph_mail=](https://plugins.trac.wordpress.org/changeset?sfp_email=&sfph_mail=&reponame=&new=3266499%40suretriggers%2Ftrunk&old=3264905%40suretriggers%2Ftrunk&sfp_email=&sfph_mail=)

---

### 22. [CVE-2025-21293](/api/vulns/CVE-2025-21293.json)

**Risk Score**: 60/100 | 
**Severity**: HIGH | 
**CVSS**: 8.8 | 
**EPSS**: 75.6%

**Summary**: Active Directory Domain Services Elevation of Privilege Vulnerability

**Risk Factors**:

- HIGH severity
- 75.6% exploit probability
- Affects critical infrastructure: microsoft

**Affected Vendors**: Microsoft

**Tags**: `CWE-284`

**References**:

- [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-21293](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-21293)

---

### 23. [CVE-2025-48828](/api/vulns/CVE-2025-48828.json)

**Risk Score**: 60/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.0 | 
**EPSS**: 67.3%

**Summary**: Certain vBulletin versions might allow attackers to execute arbitrary PHP code by abusing Template Conditionals in the template engine. By crafting template code in an alternative PHP function invocation syntax, such as the "var_dump"("test") syntax, attackers can bypass security checks and execute arbitrary PHP code, as exploited in the wild in May 2025.

**Risk Factors**:

- CRITICAL severity
- 67.34% exploit probability

**Affected Vendors**: Template, Vbulletin

**Tags**: `CWE-424`

**References**:

- [https://karmainsecurity.com/dont-call-that-protected-method-vbulletin-rce](https://karmainsecurity.com/dont-call-that-protected-method-vbulletin-rce)
- [https://kevintel.com/CVE-2025-48828](https://kevintel.com/CVE-2025-48828)

---

### 24. [CVE-2025-24865](/api/vulns/CVE-2025-24865.json)

**Risk Score**: 60/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 64.1%

**Summary**: The administrative web interface of 
mySCADA myPRO Manager

can be accessed without authentication 
which could allow an unauthorized attacker to retrieve sensitive 
information and upload files without the associated password.

**Risk Factors**:

- CRITICAL severity
- 64.09% exploit probability

**Affected Vendors**: Myscada

**Tags**: `CWE-306`

**References**:

- [https://www.cisa.gov/news-events/ics-advisories/icsa-25-044-16](https://www.cisa.gov/news-events/ics-advisories/icsa-25-044-16)
- [https://www.myscada.org/downloads/mySCADAPROManager/](https://www.myscada.org/downloads/mySCADAPROManager/)
- [https://www.myscada.org/contacts/](https://www.myscada.org/contacts/)

---

### 25. [CVE-2025-0282](/api/vulns/CVE-2025-0282.json)

**Risk Score**: 59/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.0 | 
**EPSS**: 93.2%

**Summary**: A stack-based buffer overflow in Ivanti Connect Secure before version 22.7R2.5, Ivanti Policy Secure before version 22.7R1.2, and Ivanti Neurons for ZTA gateways before version 22.7R2.3 allows a remote unauthenticated attacker to achieve remote code execution.

**Risk Factors**:

- CRITICAL severity
- 93.24% exploit probability

**Affected Vendors**: Ivanti

**Tags**: `CWE-121`

**References**:

- [https://forums.ivanti.com/s/article/Security-Advisory-Ivanti-Connect-Secure-Policy-Secure-ZTA-Gateways-CVE-2025-0282-CVE-2025-0283](https://forums.ivanti.com/s/article/Security-Advisory-Ivanti-Connect-Secure-Policy-Secure-ZTA-Gateways-CVE-2025-0282-CVE-2025-0283)

---

### 26. [CVE-2025-2011](/api/vulns/CVE-2025-2011.json)

**Risk Score**: 59/100 | 
**Severity**: HIGH | 
**CVSS**: 7.5 | 
**EPSS**: 62.6%

**Summary**: The Slider & Popup Builder by Depicter plugin for WordPress is vulnerable to generic SQL Injection via the ‘s' parameter in all versions up to, and including, 3.6.1 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

**Risk Factors**:

- HIGH severity
- 62.65% exploit probability

**Affected Vendors**: Averta, The, WordPress

**Tags**: `CWE-89`

**References**:

- [https://www.wordfence.com/threat-intel/vulnerabilities/id/49b36cde-39d8-4a69-8d7c-7b850b76a7cd?source=cve](https://www.wordfence.com/threat-intel/vulnerabilities/id/49b36cde-39d8-4a69-8d7c-7b850b76a7cd?source=cve)
- [https://plugins.trac.wordpress.org/browser/depicter/trunk/app/src/Database/Repository/LeadRepository.php?rev=3156664#L224](https://plugins.trac.wordpress.org/browser/depicter/trunk/app/src/Database/Repository/LeadRepository.php?rev=3156664#L224)
- [https://plugins.trac.wordpress.org/browser/depicter/trunk/app/src/Services/LeadService.php?rev=3156664#L82](https://plugins.trac.wordpress.org/browser/depicter/trunk/app/src/Services/LeadService.php?rev=3156664#L82)

---

### 27. [CVE-2025-27520](/api/vulns/CVE-2025-27520.json)

**Risk Score**: 59/100 | 
**Severity**: CRITICAL | 
**CVSS**: 9.8 | 
**EPSS**: 61.2%

**Summary**: BentoML is a Python library for building online serving systems optimized for AI apps and model inference. A Remote Code Execution (RCE) vulnerability caused by insecure deserialization has been identified in the latest version (v1.4.2) of BentoML. It allows any unauthenticated user to execute arbitrary code on the server. It exists an unsafe code segment in serde.py. This vulnerability is fixed in 1.4.3.

**Risk Factors**:

- CRITICAL severity
- 61.17% exploit probability

**Affected Vendors**: Bentoml, The

**Tags**: `CWE-502`

**References**:

- [https://github.com/bentoml/BentoML/security/advisories/GHSA-33xw-247w-6hmc](https://github.com/bentoml/BentoML/security/advisories/GHSA-33xw-247w-6hmc)
- [https://github.com/bentoml/BentoML/commit/b35f4f4fcc53a8c3fe8ed9c18a013fe0a728e194](https://github.com/bentoml/BentoML/commit/b35f4f4fcc53a8c3fe8ed9c18a013fe0a728e194)

---

### 28. [CVE-2025-31324](/api/vulns/CVE-2025-31324.json)

**Risk Score**: 59/100 | 
**Severity**: CRITICAL | 
**CVSS**: 10.0 | 
**EPSS**: 60.6%

**Summary**: SAP NetWeaver Visual Composer Metadata Uploader is not protected with a proper authorization, allowing unauthenticated agent to upload potentially malicious executable binaries that could severely harm the host system. This could significantly affect the confidentiality, integrity, and availability of the targeted system.

**Risk Factors**:

- CRITICAL severity
- 60.64% exploit probability

**Affected Vendors**: Development, Sap_se

**Tags**: `CWE-434`

**References**:

- [https://me.sap.com/notes/3594142](https://me.sap.com/notes/3594142)
- [https://url.sap/sapsecuritypatchday](https://url.sap/sapsecuritypatchday)

---

### 29. [CVE-2025-27363](/api/vulns/CVE-2025-27363.json)

**Risk Score**: 55/100 | 
**Severity**: HIGH | 
**CVSS**: 8.1 | 
**EPSS**: 70.7%

**Summary**: An out of bounds write exists in FreeType versions 2.13.0 and below (newer versions of FreeType are not vulnerable) when attempting to parse font subglyph structures related to TrueType GX and variable font files. The vulnerable code assigns a signed short value to an unsigned long and then adds a static value causing it to wrap around and allocate too small of a heap buffer. The code then writes up to 6 signed long integers out of bounds relative to this buffer. This may result in arbitrary cod...

**Risk Factors**:

- HIGH severity
- 70.72% exploit probability

**Affected Vendors**: Freetype

**References**:

- [https://www.facebook.com/security/advisories/cve-2025-27363](https://www.facebook.com/security/advisories/cve-2025-27363)

---

### 30. [CVE-2025-2264](/api/vulns/CVE-2025-2264.json)

**Risk Score**: 54/100 | 
**Severity**: HIGH | 
**CVSS**: 7.5 | 
**EPSS**: 69.5%

**Summary**: A Path Traversal Information Disclosure vulnerability exists in "Sante PACS Server.exe". An unauthenticated remote attacker can exploit it to download arbitrary files on the disk drive where the application is installed.

**Risk Factors**:

- HIGH severity
- 69.45% exploit probability

**Affected Vendors**: Pacs, Santesoft

**Tags**: `CWE-22`

**References**:

- [https://www.tenable.com/security/research/tra-2025-08](https://www.tenable.com/security/research/tra-2025-08)

---

## Data Sources

This briefing was generated from the following sources:


---

*This briefing was automatically generated. For the complete dataset, visit the [vulnerability dashboard](/).*