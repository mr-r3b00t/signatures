# signatures
Useful things to know about


#	Product	Cat	Ports	Detection signals	Version src	Confirm paths
1	Check Point Mobile Access / Connectra	vpn	443	cert, server, body	—	/sslvpn/Login/Login
2	Cisco ASA / AnyConnect	vpn	443	cert, cookie, body	—	/+CSCOE+/logon.html
3	Citrix NetScaler / Gateway (ADC)	vpn	443	cert, server, cookie, body	—	/vpn/index.html; /logon/LogonPoint/tmindex.html
4	F5 BIG-IP APM	vpn	443	cert, server, cookie, body	—	/my.policy
5	Fortinet FortiGate SSL-VPN	vpn	443,10443	cert, cookie, body	—	/remote/login
6	Ivanti Connect Secure / Pulse Secure	vpn	443	cert, cookie, body	path	/dana-na/auth/url_default/welcome.cgi; /dana-na/nc/nc_gina_ver.txt
7	Palo Alto GlobalProtect	vpn	443	cert, server, body	—	/global-protect/login.esp; /php/login.php
8	SonicWall SMA / SSL-VPN	vpn	443,4433	cert, server, cookie, body	—	/cgi-bin/welcome
9	VMware Horizon / UAG	vpn	443	cert, body	path	/portal/info.jsp
10	Fortinet FortiWeb (WAF)	adc	443,8443	cert, cookie, body	—	/login.html
11	Citrix ShareFile / Accellion / Kiteworks	mft	443	cert, cookie, body	—	—
12	Cleo Harmony / VLTrader / LexiCom	mft	443,5080,5443	cert, server, body	—	/Synchronization
13	Fortra GoAnywhere MFT	mft	443,8000,8001	cert, cookie, body	path	/goanywhere/
14	Progress MOVEit Transfer	mft	443	cert, server, cookie, body	path	/human.aspx; /api/v1/token
15	SolarWinds Serv-U	mft	443	cert, server, body	path	/Web Client/Login.htm
16	Microsoft Exchange (OWA/ECP)	mail	443	cookie, www-auth, body	path	/owa/; /owa/auth/logon.aspx; /ecp/; /autodiscover/autodiscover.xml
17	Roundcube Webmail	mail	443	cookie, body	homepage	—
18	Zimbra Collaboration	mail	443,7071	server, cookie, body	—	/zimbra/; /public/login.jsp
19	Ivanti EPMM / MobileIron (MDM)	mdm	443	cert, body	—	/mifs/login.jsp
20	Cisco Catalyst SD-WAN (vManage)	mgmt	443,8443	cert, body	—	/dataservice/client/server/ready; /login.html
21	Fortinet FortiClient EMS	mgmt	443	cert, body	—	/fcm/
22	Fortinet FortiSandbox	mgmt	443	cert, body	—	—
23	Kubernetes API server	mgmt	6443,443,8443	cert	path	/version; /healthz
24	Microsoft WSUS	mgmt	8530,8531,443	server	—	/ApiRemoting30/WebService.asmx; /ClientWebService/client.asmx
25	Squid proxy	mgmt	3128,443,8080	server, header, www-auth, body	homepage	—
26	Ubiquiti UniFi OS / Network	mgmt	443,8443	cert, cookie, body	path	/status; /manage/account/login
27	VMware vCenter Server	mgmt	443	cert, cookie, body	path	/sdk/vimServiceVersions.xml; /ui/
28	cPanel / WHM	mgmt	2083,2087,2096,443	server, cookie, body	—	/login/
29	Adobe Experience Manager (AEM)	cms	443,4502,4503	server, cookie, body	—	/libs/granite/core/content/login.html; /system/console
30	Drupal CMS	cms	443,80	cookie, header, body	header	/CHANGELOG.txt; /core/CHANGELOG.txt; /user/login
31	WordPress	cms	443,80	cookie, body	homepage+path	/wp-login.php; /wp-json/; /readme.html; /feed/
32	Apache Tomcat	app	443,8080,8443	server, www-auth, body	homepage+path	/docs/; /manager/html
33	Atlassian Confluence	app	443,8090	cookie, header, body	homepage+path	/login.action
34	Atlassian Jira	app	443,8080	cookie, header, body	path	/rest/api/2/serverInfo; /secure/Dashboard.jspa
35	GitLab	app	443	cookie, header, body	path	/users/sign_in; /help
36	Jenkins	app	443,8080,8443	server, header, body	header	/login
37	Microsoft SharePoint (on-prem)	app	443	cookie, header, www-auth, body	header	/_layouts/15/start.aspx; /_vti_bin/sites.asmx
38	Oracle E-Business Suite	app	443,8000	server, body	—	/OA_HTML/AppsLogin; /OA_HTML/AppsLocalLogin.jsp
39	Oracle PeopleSoft (PIA)	app	443,8000,8443	cookie, body	homepage+path	/psp/ps/?cmd=login; /psc/ps/; /PSIGW/PeopleSoftServiceListeningConnector
40	PaperCut MF/NG	app	443,9192,9191	body	homepage+path	/app; /user
41	React Server (Next.js / RSC)	app	443	header, body	—	—
42	Splunk	app	8000,8089,443	server, cookie, body	path	/en-US/account/login; /services/server/info
43	Tableau Server	app	443	cookie, body	path	/api/3.4/serverinfo; /api/2.4/serverinfo


roduct	CVE	Sev	Affected-version logic	Honeypot	Exploit-path probe
Citrix NetScaler	CVE-2025-5777	crit	13.1<58.32 · 14.1<43.56 · 13.0/12.1 EOL	ACTIVE	/p/u/doAuthentication.do
Citrix NetScaler	CVE-2023-4966	crit	13.1<49.15 · 14.1<8.50 · 13.0<92.19 · 12.1 EOL		—
Citrix NetScaler	CVE-2026-3055	crit	product-level	ACTIVE	/saml/login
Palo Alto GlobalProtect	CVE-2024-3400	crit	PAN-OS <11.1.2		—
Palo Alto GlobalProtect	CVE-2026-0257	crit	product-level	ACTIVE	/ssl-vpn/login.esp
Fortinet FortiWeb	CVE-2025-25257	crit	<7.6.4	ACTIVE	/api/fabric/device/status
Fortra GoAnywhere	CVE-2023-0669	crit	<7.1.2		—
Progress MOVEit	CVE-2023-34362	crit	<2021.0.6/2021.1.4/2022.0.4/2022.1.5/2023.0.1		—
Microsoft Exchange	CVE-2021-34473	crit	2019<15.2.792.15 · 2016<15.1.2176.12 · 2013<15.0.1497.23 · EOL		—
Ivanti EPMM	CVE-2025-4427	crit	product-level		—
Ivanti EPMM	CVE-2026-1281	crit	product-level	ACTIVE	/mifs/c/appstore/fob/
Cisco vManage	CVE-2026-20127	crit	product-level	ACTIVE	/dataservice/smartLicensing/uploadAck
FortiClient EMS	CVE-2023-48788	crit	product-level		—
FortiClient EMS	CVE-2026-35616	crit	product-level	ACTIVE	—
FortiClient EMS	CVE-2026-21643	high	product-level	ACTIVE	/api/v1/init_consts
FortiSandbox	CVE-2026-25089	crit	product-level	ACTIVE	…/phpunit/…/eval-stdin.php
FortiSandbox	CVE-2026-39808	high	product-level	ACTIVE	/fortisandbox/job-detail/
Microsoft WSUS	CVE-2025-59287	crit	product-level	ACTIVE	/ReportingWebService/ReportingWebService.asmx
Ubiquiti UniFi	CVE-2026-34910	crit	product-level	ACTIVE	/api/auth/validate-sso
cPanel / WHM	CVE-2026-41940	crit	product-level	ACTIVE	/login/
Drupal CMS	CVE-2026-9082	crit	product-level	ACTIVE	/jsonapi/node/article
Drupal CMS	CVE-2018-7600	crit	<7.58 (Drupalgeddon2)		—
Apache Tomcat	CVE-2020-1938	high	9.0<31 · 8.5<51 · 7.0<100		—
Atlassian Confluence	CVE-2023-22515	crit	<8.5.3		—
GitLab	CVE-2023-7028	crit	<16.7.2		—
Jenkins	CVE-2024-23897	high	<2.442		—
SharePoint (on-prem)	CVE-2025-53770	crit	pre-Jul-2025 builds (2016/2019/SE)		—
PaperCut MF/NG	CVE-2023-27350	crit	<20.1.7 / 21.2.11 / 22.0.9		—
React Server (Next.js)	CVE-2025-55182	crit	product-level	ACTIVE	— (honeypot POST /)
