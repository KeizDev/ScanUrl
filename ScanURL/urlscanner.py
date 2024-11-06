# OsintMx - Combined Website URL & Vulnerability Scanner
# Autonomous version without external dependencies
# Color Scheme: Violet, Light Blue, White
# -----------------------------------------------------------------------------------------------------------------------------------------------------------

try:
    import requests
    from bs4 import BeautifulSoup
    from urllib.parse import urljoin
    import re
    import time
    from datetime import datetime
except ImportError as e:
    print(f"Module import error: {e}")
    exit()

# Color Codes
violet = "\033[95m"
light_blue = "\033[94m"
white = "\033[97m"
reset = "\033[0m"

def current_time_hour():
    return datetime.now().strftime("%H:%M:%S")

def print_banner():
    print(f"{violet}OsintMx - Website URL & Vulnerability Scanner{reset}")
    print("-" * 80)

print_banner()

# Function to Find URLs
all_links = []

def find_secret_urls(website_url, domain):
    global all_links
    temp_all_links = []

    try:
        response = requests.get(website_url)
        if response.status_code != 200:
            return

        soup = BeautifulSoup(response.content, 'html.parser')

        def is_valid_extension(url):
            return re.search(r'\.(html|xhtml|php|js|css)$', url) or not re.search(r'\.\w+$', url)

        for tag in soup.find_all(['a', 'link', 'script', 'img', 'iframe', 'button', 'form']):
            href = tag.get('href')
            src = tag.get('src')
            action = tag.get('action')

            if href:
                full_url = urljoin(website_url, href)
                if full_url not in all_links and domain in full_url and is_valid_extension(full_url):
                    temp_all_links.append(full_url)
                    all_links.append(full_url)

            if src:
                full_url = urljoin(website_url, src)
                if full_url not in all_links and domain in full_url and is_valid_extension(full_url):
                    temp_all_links.append(full_url)
                    all_links.append(full_url)

            if action:
                full_url = urljoin(website_url, action)
                if full_url not in all_links and domain in full_url and is_valid_extension(full_url):
                    temp_all_links.append(full_url)
                    all_links.append(full_url)

        for form in soup.find_all('form'):
            action = form.get('action')
            if action:
                full_url = urljoin(website_url, action)
                if full_url not in all_links and domain in full_url and is_valid_extension(full_url):
                    temp_all_links.append(full_url)
                    all_links.append(full_url)

        for script in soup.find_all('script'):
            if script.string:
                urls_in_script = re.findall(r'(https?://\S+)', script.string)
                for url in urls_in_script:
                    if url not in all_links and domain in url and is_valid_extension(url):
                        temp_all_links.append(url)
                        all_links.append(url)

        for link in temp_all_links:
            print(f"{violet}[URL]{white} Found: {light_blue}{link}{reset}")
    except Exception as e:
        print(f"{violet}[ERROR]{white} Unable to retrieve URLs: {e}{reset}")

# Vulnerability Scan Functions
def Interesting_Path(url):
    interesting_paths = [
        "admin", "backup", "private", "uploads", "api", "logs", "cache", "server-status", "dashboard"
    ]
    try:
        found = 0
        if not url.endswith("/"):
            url += "/"
        
        for path in interesting_paths:
            test_url = url + path
            response = requests.get(test_url, timeout=10)
            if response.status_code == 200:
                found += 1
                print(f"{violet}[VULNERABILITY]{white} Path Found: {light_blue}/{path}{reset}")
    except Exception as e:
        print(f"{violet}[ERROR]{white} Error checking paths: {e}{reset}")
    if found == 0:
        print(f"{violet}[VULNERABILITY]{white} No Interesting Path Found.{reset}")

def Sensitive_File(url):
    sensitive_files = [
        "etc/passwd", "var/log/auth.log", "root/.bash_history", "www/html/wp-config.php"
    ]
    try:
        found = 0
        if not url.endswith("/"):
            url += "/"

        for file in sensitive_files:
            test_url = url + file
            response = requests.get(test_url, timeout=10)
            if response.status_code == 200:
                found += 1
                print(f"{violet}[VULNERABILITY]{white} Sensitive File Found: {light_blue}/{file}{reset}")
    except Exception as e:
        print(f"{violet}[ERROR]{white} Error checking files: {e}{reset}")
    if found == 0:
        print(f"{violet}[VULNERABILITY]{white} No Sensitive Files Found.{reset}")

def Sql(url):
    sql_indicators = ["SQL syntax", "SQL error", "MySQL", "mysql", "SQLSTATE"]
    sql_provocations  = ["'", '"', "' OR '1'='1'", "' OR 1=1 --"]
    try:
        found = 0
        for sql_provocation in sql_provocations:
            test_url = url + sql_provocation
            response = requests.get(test_url, timeout=10)
            if response.status_code == 200:
                for sql_indicator in sql_indicators:
                    if sql_indicator in response.text:
                        found += 1
                        print(f"{violet}[VULNERABILITY]{white} SQL Error Found: {light_blue}{sql_indicator}{reset}")
                        break
    except Exception as e:
        print(f"{violet}[ERROR]{white} Error during SQL scan: {e}{reset}")
    if found == 0:
        print(f"{violet}[VULNERABILITY]{white} No SQL Vulnerabilities Found.{reset}")

def Xss(url):
    xss_provocations = ["<script>alert('XssFound')</script>"]
    xss_indicators = ["<script>", "alert("]
    try:
        found = 0 
        for xss_provocation in xss_provocations:
            test_url = url + xss_provocation
            response = requests.get(test_url, timeout=10)
            if response.status_code == 200:
                for xss_indicator in xss_indicators:
                    if xss_indicator in response.text:
                        found += 1
                        print(f"{violet}[VULNERABILITY]{white} XSS Vulnerability Detected.{reset}")
                        break
    except Exception as e:
        print(f"{violet}[ERROR]{white} Error during XSS scan: {e}{reset}")
    if found == 0:
        print(f"{violet}[VULNERABILITY]{white} No XSS Vulnerabilities Found.{reset}")

# Main Execution
def main():
    website_url = input(f"{violet}[INPUT]{white} Website Url -> {reset}")
    if "https://" not in website_url and "http://" not in website_url:
        website_url = "https://" + website_url
    domain = re.sub(r'^https?://', '', website_url).split('/')[0]

    print(f"""
 {violet}01{white} Only "{website_url}"
 {violet}02{white} Entire Website
    """)

    choice = input(f"{violet}[INPUT]{white} Choice -> {reset}")
    if choice in ['1', '01']:
        find_secret_urls(website_url, domain)
    elif choice in ['2', '02']:
        find_secret_urls(website_url, domain)

    print(f"{violet}[INFO]{white} Starting Vulnerability Scan...{reset}")
    Sql(website_url)
    Xss(website_url)
    Interesting_Path(website_url)
    Sensitive_File(website_url)

main()
time.sleep(1000)