# edge_enum — signature & vulnerability reference

Auto-generated from `edge_signatures.py` + `edge_vulns.py`. Regenerate with `python3 gen_signature_doc.py`.

**43 detection signatures · 29 CVE rules · 15 honeypot-active CVEs · 13 exploit-path probes · 10 favicon hashes**

All detection is GET-only / unauthenticated; the tool runs dry-run unless `--authorised "<ref>"` is passed.

## A. Detection signatures

| # | Product | Cat | Ports | Detection signals | Version src | Favicon (mmh3) | Confirm paths |
|---|---|---|---|---|---|---|---|
| 1 | Check Point Mobile Access / Connectra | vpn | 443 | cert, server, body | — | -1822098181 | `/sslvpn/Login/Login` |
| 2 | Cisco ASA / AnyConnect | vpn | 443 | cert, cookie, body | — | — | `/+CSCOE+/logon.html` |
| 3 | Citrix NetScaler / Gateway (ADC) | vpn | 443 | cert, server, cookie, body | — | -1292923998, -1166125415, 2053741851 | `/vpn/index.html; /logon/LogonPoint/tmindex.html` |
| 4 | F5 BIG-IP APM | vpn | 443 | cert, server, cookie, body | — | 878647854, 1888970943 | `/my.policy` |
| 5 | Fortinet FortiGate SSL-VPN | vpn | 443,10443 | cert, cookie, body | — | — | `/remote/login` |
| 6 | Ivanti Connect Secure / Pulse Secure | vpn | 443 | cert, cookie, body | path | — | `/dana-na/auth/url_default/welcome.cgi; /dana-na/nc/nc_gina_ver.txt` |
| 7 | Palo Alto GlobalProtect | vpn | 443 | cert, server, body | — | — | `/global-protect/login.esp; /php/login.php` |
| 8 | SonicWall SMA / SSL-VPN | vpn | 443,4433 | cert, server, cookie, body | — | 778117213 | `/cgi-bin/welcome` |
| 9 | VMware Horizon / UAG | vpn | 443 | cert, body | path | — | `/portal/info.jsp` |
| 10 | Fortinet FortiWeb (WAF) | adc | 443,8443 | cert, cookie, body | — | — | `/login.html` |
| 11 | Citrix ShareFile / Accellion / Kiteworks | mft | 443 | cert, cookie, body | — | — | `—` |
| 12 | Cleo Harmony / VLTrader / LexiCom | mft | 443,5080,5443 | cert, server, body | — | — | `/Synchronization` |
| 13 | Fortra GoAnywhere MFT | mft | 443,8000,8001 | cert, cookie, body | path | — | `/goanywhere/` |
| 14 | Progress MOVEit Transfer | mft | 443 | cert, server, cookie, body | path | — | `/human.aspx; /api/v1/token` |
| 15 | SolarWinds Serv-U | mft | 443 | cert, server, body | path | — | `/Web Client/Login.htm` |
| 16 | Microsoft Exchange (OWA/ECP) | mail | 443 | cookie, www-auth, body | path | 1768726119 | `/owa/; /owa/auth/logon.aspx; /ecp/; /autodiscover/autodiscover.xml` |
| 17 | Roundcube Webmail | mail | 443 | cookie, body | homepage | — | `—` |
| 18 | Zimbra Collaboration | mail | 443,7071 | server, cookie, body | — | — | `/zimbra/; /public/login.jsp` |
| 19 | Ivanti EPMM / MobileIron (MDM) | mdm | 443 | cert, body | — | 1983356674 | `/mifs/login.jsp` |
| 20 | Cisco Catalyst SD-WAN (vManage) | mgmt | 443,8443 | cert, body | — | — | `/dataservice/client/server/ready; /login.html` |
| 21 | Fortinet FortiClient EMS | mgmt | 443 | cert, body | — | — | `/fcm/` |
| 22 | Fortinet FortiSandbox | mgmt | 443 | cert, body | — | — | `—` |
| 23 | Kubernetes API server | mgmt | 6443,443,8443 | cert | path | — | `/version; /healthz` |
| 24 | Microsoft WSUS | mgmt | 8530,8531,443 | server | — | — | `/ApiRemoting30/WebService.asmx; /ClientWebService/client.asmx` |
| 25 | Squid proxy | mgmt | 3128,443,8080 | server, header, www-auth, body | homepage | — | `—` |
| 26 | Ubiquiti UniFi OS / Network | mgmt | 443,8443 | cert, cookie, body | path | — | `/status; /manage/account/login` |
| 27 | VMware vCenter Server | mgmt | 443 | cert, cookie, body | path | — | `/sdk/vimServiceVersions.xml; /ui/` |
| 28 | cPanel / WHM | mgmt | 2083,2087,2096,443 | server, cookie, body | — | — | `/login/` |
| 29 | Adobe Experience Manager (AEM) | cms | 443,4502,4503 | server, cookie, body | — | — | `/libs/granite/core/content/login.html; /system/console` |
| 30 | Drupal CMS | cms | 443,80 | cookie, header, body | header | — | `/CHANGELOG.txt; /core/CHANGELOG.txt; /user/login` |
| 31 | WordPress | cms | 443,80 | cookie, body | homepage+path | — | `/wp-login.php; /wp-json/; /readme.html; /feed/` |
| 32 | Apache Tomcat | app | 443,8080,8443 | server, www-auth, body | homepage+path | -297069493 | `/docs/; /manager/html` |
| 33 | Atlassian Confluence | app | 443,8090 | cookie, header, body | homepage+path | — | `/login.action` |
| 34 | Atlassian Jira | app | 443,8080 | cookie, header, body | path | — | `/rest/api/2/serverInfo; /secure/Dashboard.jspa` |
| 35 | GitLab | app | 443 | cookie, header, body | path | -1119287757 | `/users/sign_in; /help` |
| 36 | Jenkins | app | 443,8080,8443 | server, header, body | header | 81586312 | `/login` |
| 37 | Microsoft SharePoint (on-prem) | app | 443 | cookie, header, www-auth, body | header | — | `/_layouts/15/start.aspx; /_vti_bin/sites.asmx` |
| 38 | Oracle E-Business Suite | app | 443,8000 | server, body | — | — | `/OA_HTML/AppsLogin; /OA_HTML/AppsLocalLogin.jsp` |
| 39 | Oracle PeopleSoft (PIA) | app | 443,8000,8443 | cookie, body | homepage+path | — | `/psp/ps/?cmd=login; /psc/ps/; /PSIGW/PeopleSoftServiceListeningConnector` |
| 40 | PaperCut MF/NG | app | 443,9192,9191 | body | homepage+path | — | `/app; /user` |
| 41 | React Server (Next.js / RSC) | app | 443 | header, body | — | — | `—` |
| 42 | Splunk | app | 8000,8089,443 | server, cookie, body | path | — | `/en-US/account/login; /services/server/info` |
| 43 | Tableau Server | app | 443 | cookie, body | path | -1441956789 | `/api/3.4/serverinfo; /api/2.4/serverinfo` |

**Detection signals** — regex evidence types: `cert` (subject/issuer/SAN), `server` (Server header), `cookie` (Set-Cookie), `header` (any response header, e.g. `X-Jenkins`, `MicrosoftSharePointTeamServices`), `www-auth` (WWW-Authenticate), `body` (root HTML). Reported only at confidence ≥ 3 (single weak signals don't fire). **Version src** — where a build is read unauthenticated (`homepage` is CDN-safe).

## B. Vulnerability + active-exploitation logic

| Product | CVE | Sev | Affected-version logic | Honeypot | Exploit-path probe |
|---|---|---|---|---|---|
| Citrix NetScaler / Gateway (ADC) | CVE-2025-5777 | crit | 13.1<58.32 · 14.1<43.56 · 13.0/12.1 EOL | **ACTIVE** | `/p/u/doAuthentication.do` |
| Citrix NetScaler / Gateway (ADC) | CVE-2023-4966 | crit | 13.1<49.15 · 14.1<8.50 · 13.0<92.19 · 12.1 EOL |  | — |
| Citrix NetScaler / Gateway (ADC) | CVE-2026-3055 | crit | product-level | **ACTIVE** | `/saml/login` |
| Palo Alto GlobalProtect | CVE-2024-3400 | crit | PAN-OS <11.1.2 (coarse) |  | — |
| Palo Alto GlobalProtect | CVE-2026-0257 | crit | product-level | **ACTIVE** | `/ssl-vpn/login.esp` |
| Fortinet FortiWeb (WAF) | CVE-2025-25257 | crit | <7.6.4 (coarse) | **ACTIVE** | `/api/fabric/device/status` |
| Fortra GoAnywhere MFT | CVE-2023-0669 | crit | <7.1.2 |  | — |
| Progress MOVEit Transfer | CVE-2023-34362 | crit | <2021.0.6/2021.1.4/2022.0.4/2022.1.5/2023.0.1 |  | — |
| Microsoft Exchange (OWA/ECP) | CVE-2021-34473 | crit | 2019<15.2.792.15 · 2016<15.1.2176.12 · 2013<15.0.1497.23 · 2010/07 EOL |  | — |
| Ivanti EPMM / MobileIron (MDM) | CVE-2025-4427 | crit | product-level |  | — |
| Ivanti EPMM / MobileIron (MDM) | CVE-2026-1281 | crit | product-level | **ACTIVE** | `/mifs/c/appstore/fob/` |
| Cisco Catalyst SD-WAN (vManage) | CVE-2026-20127 | crit | product-level | **ACTIVE** | `/dataservice/smartLicensing/uploadAck` |
| Fortinet FortiClient EMS | CVE-2023-48788 | crit | product-level |  | — |
| Fortinet FortiClient EMS | CVE-2026-35616 | crit | product-level | **ACTIVE** | — |
| Fortinet FortiClient EMS | CVE-2026-21643 | high | product-level | **ACTIVE** | `/api/v1/init_consts` |
| Fortinet FortiSandbox | CVE-2026-25089 | crit | product-level | **ACTIVE** | `/api/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` |
| Fortinet FortiSandbox | CVE-2026-39808 | high | product-level | **ACTIVE** | `/fortisandbox/job-detail/` |
| Microsoft WSUS | CVE-2025-59287 | crit | product-level | **ACTIVE** | `/ReportingWebService/ReportingWebService.asmx` |
| Ubiquiti UniFi OS / Network | CVE-2026-34910 | crit | product-level | **ACTIVE** | `/api/auth/validate-sso` |
| cPanel / WHM | CVE-2026-41940 | crit | product-level | **ACTIVE** | `/login/` |
| Drupal CMS | CVE-2026-9082 | crit | product-level | **ACTIVE** | `/jsonapi/node/article` |
| Drupal CMS | CVE-2018-7600 | crit | <7.58 (Drupalgeddon2) |  | — |
| Apache Tomcat | CVE-2020-1938 | high | 9.0<31 · 8.5<51 · 7.0<100 |  | — |
| Atlassian Confluence | CVE-2023-22515 | crit | <8.5.3 (coarse) |  | — |
| GitLab | CVE-2023-7028 | crit | <16.7.2 (coarse) |  | — |
| Jenkins | CVE-2024-23897 | high | <2.442 (coarse) |  | — |
| Microsoft SharePoint (on-prem) | CVE-2025-53770 | crit | pre-Jul-2025 builds (2016/2019/SE) |  | — |
| PaperCut MF/NG | CVE-2023-27350 | crit | <20.1.7 / 21.2.11 / 22.0.9 |  | — |
| React Server (Next.js / RSC) | CVE-2025-55182 | crit | product-level | **ACTIVE** | — |

**Affected-version logic** — build comparison applied when a version is read; otherwise status is *exposed* (honeypot-active) or *version-unknown*. `product-level` = no public version range (2026 honeypot CVEs are simulated). **Honeypot ACTIVE** = currently exploited in the `export-25.csv` decoy feed. **Exploit-path probe** = sanitised (no payload/traversal) GET confirming the vulnerable surface is reachable.

## Status tiers (per finding)

- `!! VULNERABLE` — detected build is in the affected range (confirmed).
- `!  exposed [EXPLOITED-IN-WILD]` — product reachable + CVE live in the honeypot; build not range-checkable.
- `?  check` — known CVE for the product, version not readable, not currently seen exploited.

## Favicon hashing

`/favicon.ico` is fetched and hashed Shodan-style (mmh3 of the base64-encoded icon, signed). Hashes are seeded from the estate's own Shodan data (`favicon_seed.json`) plus well-known public values, and matched as a strong (weight-3) signal — so an appliance is identified even behind a generic login page. The computed hash is recorded on every finding for collection/extension.

## Not yet implemented

- **JA3 / JARM** TLS fingerprinting — not used.
- **SMTP banner mode** (port 25/465/587 — Exim/Postfix/Exchange version) — not implemented (the discovery data is heavily Exim, so this is the biggest coverage gap).

