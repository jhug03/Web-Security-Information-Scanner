import requests # Used to get headers
import webtech
import ssl
import socket
import re
import sys
import mmh3
import codecs
import time
from pathlib import Path
import shutil

from urllib.parse import urlparse
from datetime import datetime
from bs4 import BeautifulSoup, Comment
from urllib.parse import urljoin

# Colours
RED = "\033[91m"
RESET = "\033[0m"
GRAY = "\033[90m"
GREEN = "\033[32m"
ORANGE = "\033[38;2;255;165;0m"
BLUE = "\033[34m"

# Logging
class LogTee:
    def __init__(self, terminal, log_file):
        self.terminal = terminal
        self.log_file = log_file

    def write(self, text):
        self.terminal.write(text)
        self.log_file.write(re.sub(r"\033\[[0-9;]*m", "", text))

    def flush(self):
        self.terminal.flush()
        self.log_file.flush()

# Agree to not scanning unauthorised websites
def agreeToPrivacy():
    print(f"{RED}[!] \n----------------------------------------\nThis tool should only be utilised on websites you are authorised to scan.\nScanning unauthorised websites may be illegal.\n----------------------------------------{RESET}")
    
    agreeToPrivacyInput = input('\nAgree to above? (y/n):')
    
    if (agreeToPrivacyInput == 'y'):
        return
    else: # If user doesn't type anything but y
        print(f"{RED}[!] You need to agree to the above before you can use this tool{RESET}")
        exit() # Quit
        
# Handle clearing the logs or scanning a website
def startOptions():
    print('\nPlease choose an option:\n1 - Scan a website\n2 - Clear log files')
    whichOption = input('Enter: ')
    
    if (whichOption == '1'):
        return # Return to where the function was called from which carries on with the natural flow of the program
        
    if (whichOption == '2'):
        print(f"{RED}[!] Clearing log files{RESET}")
        shutil.rmtree("logs") # Remove the logs folder
        
        folder = Path(__file__).parent / "logs" # Grab the logs folder
        
        # Check to see if it has been deleted or not
        if folder.is_dir():
            print(f"{RED}[!] Folder could not be deleted{RESET}")
        else:
            print(f"{GREEN}[+] Folder deleted successfully{RESET}")
            
        exit() # Exit regardless
        
    else: # Exit if 1 or 2 was not chosen
        print(f"{RED}[!] You need to choose an option. Exiting...{RESET}")
        exit() # Quit
        
#  Handle getting the website the user wants to scan
def grabWebsite():
    extensions = ['.com', '.co.uk', '.org', '.net', '.io', 'https://', 'http://'] # Site extensions
    
    getWebsite = input('\nTARGET URL ➤ ')
    print(f"{GRAY}[.] {getWebsite}{RESET}")
    
    if not getWebsite: # If user doesn't enter anything
        print(f"{RED}[!] Input is empty. Exiting...{RESET}")
        exit()

    if not any(extension in getWebsite for extension in extensions): # If domain extension or https/http is missing
        print(f"{RED}[!] Input does not contain domain extension and/or https/http Exiting...{RESET}")
        exit()

    return getWebsite # Returning the stored website allows the program to pass the inputted website around without declaring it globally

# Check if the website is even valid
def checkValidWebsite(getWebsite):
    print(f"{GRAY}[.] Checking if website is valid{RESET}")
    
    try:
        response = requests.get(getWebsite, timeout=10) # Send a request to the site with a 10 sec timeout

        print(f"{GRAY}[.] Website status: {response.status_code}{RESET}") # Display response code

        if response.ok: # If response is ok
            print(f"{GREEN}[+] Website is reachable.{RESET}")
        else:
            print(f"{RED}[!] Website returned an error. Exiting...{RESET}")
            exit() # Quit if no response

        return response

    except requests.RequestException:
        print(f"{RED}[!] Website could not be reached. Exiting...{RESET}")
        exit()


# Scan site headers
def headerScan(getWebsite, response):
    # Each header defines what its presence/absence means.
    #
    # "present_good" = True  -> presence is good, absence is a warning
    # "present_good" = False -> presence is not desirable, absence is good
    # "conditional" = True   -> presence/absence is informational

    security_headers = {
        # Security headers
        "Strict-Transport-Security": {
            "present_good": True,
            "missing_message": "HSTS is missing"
        },

        "Content-Security-Policy": {
            "present_good": True,
            "missing_message": "CSP is missing"
        },

        "X-Content-Type-Options": {
            "present_good": True,
            "missing_message": "X-Content-Type-Options is missing"
        },

        "X-Frame-Options": {
            "present_good": True,
            "missing_message": "X-Frame-Options is missing"
        },

        "Referrer-Policy": {
            "present_good": True,
            "missing_message": "Referrer-Policy is missing"
        },

        "Permissions-Policy": {
            "present_good": True,
            "missing_message": "Permissions-Policy is missing"
        },

        # Cross-origin headers
        "Cross-Origin-Opener-Policy": {
            "present_good": True,
            "missing_message": "COOP is missing"
        },

        "Cross-Origin-Resource-Policy": {
            "present_good": True,
            "missing_message": "CORP is missing"
        },

        "Cross-Origin-Embedder-Policy": {
            "present_good": True,
            "missing_message": "COEP is missing"
        },

        # Conditional headers
        "Cache-Control": {
            "conditional": True
        },

        "Pragma": {
            "conditional": True
        },

        "Content-Disposition": {
            "conditional": True
        },

        "Reporting-Endpoints": {
            "conditional": True
        },

        "NEL": {
            "conditional": True
        },

        # Deprecated headers
        "Expect-CT": {
            "present_good": False,
            "missing_message": "Expect-CT is not present"
        },

        "X-XSS-Protection": {
            "present_good": False,
            "missing_message": "X-XSS-Protection is not present"
        },

        "X-Permitted-Cross-Domain-Policies": {
            "present_good": True,
            "missing_message": "X-Permitted-Cross-Domain-Policies is missing"
        },

        "X-Download-Options": {
            "present_good": True,
            "missing_message": "X-Download-Options is missing"
        }
    }

    headers = response.headers

    if not headers:
        print(
            f"{RED}[!] Could not get website headers "
            f"despite website being reachable{RESET}"
        )
        return

    print("\nHeaders")
    
    print(f"{GRAY}[i] Website headers found{RESET}")
    
    for header, config in security_headers.items():

        present = header in headers

        # Conditional header
        if config.get("conditional"):
            if present:
                print(
                    f"{BLUE}[i] {header} is present{RESET}"
                )
            else:
                print(
                    f"{BLUE}[i] {header} is missing{RESET}"
                )
            continue

        # Header whose presence is good
        if config["present_good"]:
            if present:
                print(
                    f"{GREEN}[+] {header} is present{RESET}"
                )
            else:
                print(
                    f"{ORANGE}[~] {config['missing_message']}{RESET}"
                )

        # Header whose absence is good
        else:
            if present:
                print(
                    f"{ORANGE}[~] {header} is present "
                    f"(legacy/deprecated){RESET}"
                )
            else:
                print(
                    f"{GREEN}[+] {config['missing_message']}{RESET}"
                )

# Get the web technologies used on the site
# This is a WIP and doesn't display a lot right now
# Use a library called webtech
def getWebTechnologies(getWebsite):
    print(f"\nWeb technologies")
    
    wt = webtech.WebTech(options={'json': True})

    try:
        result = wt.start_from_url(getWebsite) # Scan the website using webtech for technologies
        print(f"{GREEN}[+] Web technologies found{RESET}")
        
        technologies = result.get('tech', [])
        
        for item in technologies: # Loop the found items in stored technologies
            name = item.get('name', 'Unknown')
            
            print(f"{GRAY}[.] - {name}{RESET}") # Print found technologies
            
    except Exception as e: # If no technologies found
        print(f"{ORANGE}[~] No web technologies found: {e}{RESET}")

# Get site certifications
def getCert(getWebsite):
    print("\nCertificate")
    parsed = urlparse(getWebsite) # Parse the website URL
    if parsed.scheme != "https": # Check if site uses https
        print(f"{GRAY}[.] TLS certificate: Not applicable (HTTP){RESET}")
        return

    hostname = parsed.hostname # Get the website hostname

    context = ssl.create_default_context() # Create a secure SSL context

    # Connect to the website
    with socket.create_connection((hostname, 443), timeout=10) as sock:

        # Create a secure TLS connection
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:

            certificate = ssock.getpeercert() # Get the website's certificate

            # Show the TLS version and cipher used
            print(f"{GRAY}[.] TLS Version: {ssock.version()}{RESET}")
            print(f"{GRAY}[.] Cipher: {ssock.cipher()[0]}{RESET}")

            # Get the certificate issuer
            issuer = ", ".join(
                f"{name}: {value}"
                for item in certificate["issuer"]
                for name, value in item
            )

            # Get the certificate subject
            subject = ", ".join(
                f"{name}: {value}"
                for item in certificate["subject"]
                for name, value in item
            )

            # Display certificate information
            print(f"{GRAY}[.] Issuer: {issuer}{RESET}")
            print(f"{GRAY}[.] Valid from: {certificate['notBefore']}{RESET}")
            print(f"{GRAY}[.] Valid until: {certificate['notAfter']}{RESET}")
            print(f"{GRAY}[.] Subject: {subject}{RESET}")

# Get robots.txt and sitemap.xml
def getRobots(getWebsite):
    print(f"\nRobots and sitemap")
    
    # Get the two files
    robots = requests.get(f"{getWebsite}/robots.txt", timeout=10)
    sitemap = requests.get(f"{getWebsite}/sitemap.xml", timeout=10)
    
    if robots.status_code == 200: # If robots is found
        print(f"{BLUE}[!] robots.txt found{RESET}")
    else:
        print(f"{ORANGE}[~] robots.txt not found{RESET}")

    if sitemap.status_code == 200: # If sitemap is found
        print(f"{BLUE}[!] sitemap.xml found{RESET}")
    else:
        print(f"{ORANGE}[~] sitemap.xml not found{RESET}")

# Check if any cookies are found on the site
def checkCookies(getWebsite, response):
    print(f"\nCookies")
    
    cookies = response.cookies # Get the cookies

    if not cookies: # If no cookies are found
        print(f"{GREEN}[+] No cookies found{RESET}")
        return

    for cookie in cookies: # Loop the found cookies
        print(f"{GRAY}[.] Cookie: {cookie.name}{RESET}")

        if cookie.secure:
            print(f"{GREEN}[+] Secure: Yes{RESET}")
        else:
            print(f"{RED}[!] Secure: No{RESET}")

        if cookie.has_nonstandard_attr("HttpOnly"):
            print(f"{GREEN}[+] HttpOnly: Yes{RESET}")
        else:
            print(f"{RED}[!] HttpOnly: No{RESET}")

def checkMethods(getWebsite):
    print(f"\nMethods")
    
    response = requests.options(getWebsite, timeout=10) # Get the response using requests from the site with a 10sec timeout

    methods = response.headers.get("Allow") # Get headers

    if methods:
        print(f"{GRAY}[.] Allowed methods: {methods}{RESET}")
    else:
        print(f"{GREEN}[+] Allowed methods not disclosed{RESET}")
        
# Get site CORS. Stands for Cross-Origin Resource Sharing.
# CORS is a browser security mechanism that controls whether JavaScript is allowed to read responses from a different website.
def checkCORS(getWebsite, response):
    print("\nCORS")
    cors = response.headers.get("Access-Control-Allow-Origin")

    if cors:
        print(f"{GRAY}[.] CORS: {cors}{RESET}")

        if cors == "*":
            print(f"{ORANGE}[~] CORS allows all origins{RESET}")
        else:
            print(f"{GREEN}[+] CORS origin restricted{RESET}")
    else:
        print(f"{BLUE}[i] CORS: Not configured{RESET}")


# Page structure and form checks
# Get general information about the page
def getPageInfo(getWebsite, response):
    print(f"\nGeneral info{RESET}")
    
    soup = BeautifulSoup(response.text, "html.parser")

    title = soup.title.string.strip() if soup.title else "No title"
    content_type = response.headers.get("Content-Type", "Unknown")
    page_size = len(response.content)

    print(f"{GRAY}[.] Page title: {title}{RESET}")
    print(f"{GRAY}[.] Content-Type: {content_type}{RESET}")
    print(f"{GRAY}[.] Page size: {page_size} bytes{RESET}")
    
def checkForms(getWebsite, response):
    print(f"\nForms")
    
    soup = BeautifulSoup(response.text, "html.parser")

    forms = soup.find_all("form")

    print(f"{GRAY}[.] Forms found: {len(forms)}{RESET}")

    for form in forms:
        action = form.get("action", "")
        method = form.get("method", "GET").upper()

        action_url = urljoin(getWebsite, action)

        print(f"{GRAY}[.] Form action: {action_url}{RESET}")
        print(f"{GRAY}[.] Method: {method}{RESET}")

        password = form.find("input", {"type": "password"})

        if password:
            if action_url.startswith("http://"):
                print(f"{RED}[!] Password form submits over HTTP.{RESET}")
            else:
                print(f"{GREEN}[+] Password form submits over HTTPS.{RESET}")
                
def checkAccessKey(getWebsite, response):
    print(f"\nLeaked keys")

    soup = BeautifulSoup(response.text, "html.parser")

    names = [
        "access-key",
        "access_key",
        "accessKey",
        "accesskey",
        "api-key",
        "api_key",
        "apiKey",
        "apikey"
    ]

    found = False

    for name in names:
        access_key = soup.find("input", {"name": name})

        if access_key and access_key.get("value"):
            print(
                f"{RED}[!] The value '{name}' in a form is exposed{RESET}"
            )
            found = True

    if not found:
        print(f"{GREEN}[+] No access keys found{RESET}")
            
def checkMixedContent(response):
    print(f"\nMixed Content")
    
    soup = BeautifulSoup(response.text, "html.parser")

    found = False

    for tag in soup.find_all(["script", "img", "link", "iframe"]):
        url = tag.get("src") or tag.get("href")

        if url and url.startswith("http://"):
            print(f"{RED}[!] Mixed content: {url}{RESET}")
            found = True

    if not found:
        print(f"{GREEN}[+] No mixed content found. Site does not load resources over plain HTTP{RESET}")
        
def checkExternalScripts(getWebsite, response):
    print(f"\nExternal scripts")
    
    soup = BeautifulSoup(response.text, "html.parser")
    
    found = False

    for script in soup.find_all("script"):
        src = script.get("src")

        if src:
            print(f"{ORANGE}[~] Script: {src}{RESET}")
            found = True
            
    if not found:
        print(f"{GREEN}[+] No external scripts found{RESET}")
            
def checkSRI(getWebsite, response):
    print(f"\nSRI")
    
    soup = BeautifulSoup(response.text, "html.parser")

    found = False

    for tag in soup.find_all(["script", "link"]):
        url = tag.get("src") or tag.get("href")

        if url and url.startswith("http"):
            found = True

            if tag.get("integrity"):
                print(f"{GREEN}[+] SRI: PRESENT - {url}{RESET}")
            else:
                print(f"{ORANGE}[~] SRI missing on - {url}{RESET}")
                
    if not found:
        print(f"{GRAY}[.] No external resources found.{RESET}")
        
def checkComments(getWebsite, response):
    print(f"\nComments")
    
    soup = BeautifulSoup(response.text, "html.parser")

    comments = soup.find_all(string=lambda text: isinstance(text, Comment))

    found = False

    for comment in comments:
        text = comment.strip()

        if len(text) < 5:
            continue

        print(f"{ORANGE}[~] Comment: {text}{RESET}")
        found = True

    if not found:
        print(f"{GREEN}[+] No useful comments found.{RESET}")
        
def checkDirectoryListing(getWebsite):
    print(f"\nDirectory listings")
    
    paths = [
        "/uploads/",
        "/files/",
        "/backup/",
        "/backups/",
        "/assets/",
        "/images/"
    ]

    for path in paths:
        response = requests.get(getWebsite + path, timeout=10)

        if response.status_code == 200 and "Index of /" in response.text:
            print(f"{RED}[!] Directory listing exposed: {path}{RESET}")
        else:
            print(f"{GRAY}[.] No directory listing: {path}{RESET}")
            
def checkSensitiveFiles(getWebsite):
    print(f"Sensitive files")
    
    files = [
        "/.env",
        "/.git/HEAD",
        "/phpinfo.php",
        "/server-status",
        "/backup.zip"
    ]

    for file in files:
        url = getWebsite.rstrip("/") + file
        response = requests.get(url, timeout=10)

        if response.status_code == 200:
            print(f"{ORANGE}[~] {file}: FOUND{RESET}")
            print(f"{GRAY}[.] Location: {url}{RESET}")
        elif response.status_code == 404:
            print(f"{GREEN}[+] {file}: Not found{RESET}")
        else:
            print(f"{GRAY}[.] {file}: HTTP {response.status_code}{RESET}")

def getDNS(getWebsite):
    print(f"\nDNS")
    
    hostname = urlparse(getWebsite).hostname

    try:
        ip = socket.gethostbyname(hostname)

        print(f"{GRAY}[.] IP Address: {ip}{RESET}")

    except socket.gaierror:
        print(f"{RED}[!] Could not resolve hostname.{RESET}")
        
def findEmails(getWebsite, response):
    print(f"\nEmails")
    
    emails = re.findall(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        response.text
    )

    emails = set(emails)

    if emails:
        emailCount = len(emails)
        print(f"{GRAY}[.] Found {emailCount} emails{RESET}")

        sorted_emails = sorted(emails)

        for email in sorted_emails:
            print(f"{ORANGE}[~] Email found: {email}{RESET}")
            
    else:
        print(f"{GREEN}[+] No email addresses found.{RESET}")

def checkInsecureForms(getWebsite, response):
    print(f"\nInsecure forms")
    
    soup = BeautifulSoup(response.text, "html.parser")

    found = False

    for form in soup.find_all("form"):
        action = form.get("action", "")

        if action.startswith("http://"):
            print(f"{RED}[!] Insecure form: {action}{RESET}")
            found = True

    if not found:
        print(f"{GREEN}[+] No insecure forms found.{RESET}")
        
def checkSecurityTxt(getWebsite):
    print(f"\nSecurity.txt")
    
    url = getWebsite.rstrip("/") + "/.well-known/security.txt"

    response = requests.get(url, timeout=10)

    if response.status_code == 200:
        print(f"{ORANGE}[~] security.txt found{RESET}")
        print(f"{ORANGE}[~] Location: {url}{RESET}")
    elif response.status_code == 404:
        print(f"{GREEN}[+] security.txt not found{RESET}")
    else:
        print(f"{GRAY}[.] security.txt: HTTP {response.status_code}{RESET}")

def checkPasswordAutocomplete(getWebsite, response):
    print(f"\nPassword autocomplete")
    
    soup = BeautifulSoup(response.text, "html.parser")

    found = False

    for password in soup.find_all("input", {"type": "password"}):
        found = True
        autocomplete = password.get("autocomplete")

        if autocomplete == "off":
            print(f"{GREEN}[+] Password field: autocomplete=off{RESET}")
        elif autocomplete:
            print(f"{ORANGE}[~] Password field: autocomplete={autocomplete}{RESET}")
        else:
            print(f"{GRAY}[.] Password field: autocomplete not specified{RESET}")

    if not found:
        print(f"{GREEN}[+] No password autocomplete fields found{RESET}")


# Page assets and metadata
def getFaviconHash(getWebsite, response):
    print(f"\nFavicon fingerprinting")
    
    soup = BeautifulSoup(response.text, "html.parser")
    favicon_url = None

    for link in soup.find_all("link"):
        rel = link.get("rel", [])
        if any(r in rel for r in ["icon", "shortcut icon", "apple-touch-icon"]):
            favicon_url = link.get("href")
            break

    if not favicon_url:
        favicon_url = "/favicon.ico"

    full_favicon_url = urljoin(getWebsite, favicon_url)

    try:
        fav_response = requests.get(full_favicon_url, timeout=10)
        if fav_response.status_code == 200:
            favicon_base64 = codecs.encode(fav_response.content, "base64")
            
            hash_value = mmh3.hash(favicon_base64)
            
            print(f"{GRAY}[.] Favicon found at: {full_favicon_url}{RESET}")
            print(f"{ORANGE}[~] Favicon MurmurHash3: {hash_value}{RESET}")
            
            shodan_url = f"https://www.shodan.io/search?query=http.favicon.hash%3A{hash_value}"
            print(f"{GRAY}[.] Shodan Search Link. You need to be logged into Shodan to use this feature and it may return no results: {ORANGE}[~] {shodan_url}{RESET}")
        else:
            print(f"{ORANGE}[~] Favicon could not be retrieved (HTTP {fav_response.status_code}){RESET}")
    except Exception as e:
        print(f"{ORANGE}[~] Error retrieving favicon: {e}{RESET}")


def checkPerformanceReport(response):
    print(f"\nPerformance")
    
    elapsed_time_ms = response.elapsed.total_seconds() * 1000
    
    content_size_bytes = len(response.content)
    content_size_kb = content_size_bytes / 1024
    
    content_encoding = response.headers.get("Content-Encoding", "None")
    
    print(f"{GRAY}[.] Performance and speed analysis:{RESET}")
    print(f"{GRAY}[.] - Response Time (Latency): {GREEN}[+] {elapsed_time_ms:.2f} ms{RESET}")
    print(f"{GRAY}[.] - Main Page Size: {GREEN}[+] {content_size_kb:.2f} KB{RESET}")
    
    if content_encoding != "None":
        print(f"{GRAY}[.] - Text Compression: {GREEN}[+] Enabled ({content_encoding}){RESET}")
    else:
        print(f"{GRAY}[.] - Text Compression: {ORANGE}[~] Disabled (Missing Content-Encoding){RESET}")


# Site discovery and exposed resources
def discoverSubdomains(getWebsite, response):
    print(f"\nSubdomains{RESET}")

    sensitive_paths = {
        '/admin', '/administrator', '/api', '/backup',
        '/backups', '/config', '/dashboard', '/db', '/debug',
        '/env', '/graphql', '/internal', '/phpmyadmin', '/secret',
        '/staging', '/test', '/vault', '/wp-admin'
    }

    base_url = urlparse(getWebsite)
    base_hostname = (base_url.hostname or "").lower()
    paths = set()
    subdomains = set()
    soup = BeautifulSoup(response.text, "html.parser")

    for anchor in soup.find_all("a", href=True):
        link = urljoin(getWebsite, anchor["href"])
        parsed_link = urlparse(link)

        if parsed_link.scheme not in {"http", "https"}:
            continue

        hostname = (parsed_link.hostname or "").lower()
        if not hostname:
            continue

        if hostname == base_hostname:
            path = parsed_link.path or "/"
            if parsed_link.query:
                path = f"{path}?{parsed_link.query}"
            paths.add(path)
        elif hostname.endswith(f".{base_hostname}"):
            subdomains.add(parsed_link.netloc)

    if paths:
        print(f"{GRAY}[.] Linked pages found:{RESET}")

        for path in sorted(paths):
            if path in sensitive_paths:
                print(f"{RED}[!] {path}{RESET}")
            else:
                print(f"{GRAY}[.] {path}{RESET}")
    else:
        print(f"{GREEN}[+] No linked paths found{RESET}")

    if subdomains:
        print(f"{GRAY}[.] Linked pages found:{RESET}")
        for subdomain in sorted(subdomains):
            print(f"{GRAY}[.] {subdomain}{RESET}")
    else:
        print(f"{GREEN}[+] No linked subdomains found{RESET}")


# Program entry point
if __name__ == "__main__":
    logs_directory = Path(__file__).resolve().parent / "logs"
    logs_directory.mkdir(exist_ok=True)
    log_filename = datetime.now().strftime("scan_%Y-%m-%d_%H-%M-%S-%f.txt")

    with open(logs_directory / log_filename, "w", encoding="utf-8") as log_file:
        original_stdout = sys.stdout
        original_stderr = sys.stderr
        sys.stdout = LogTee(original_stdout, log_file)
        sys.stderr = LogTee(original_stderr, log_file)

        try:
            startOptions() # Choose whether to scan or clear logs
            agreeToPrivacy() # Check if user agrees to not scanning random targets
            getWebsite = grabWebsite() # Grab the website the user wants to scan but only if they agree above. Setup variable here first so it can be passed on without global initalisation.
            response = checkValidWebsite(getWebsite) # Check if the website is valid

            # Connection and transport security
            headerScan(getWebsite, response) # Get the headers from the site
            getCert(getWebsite) # Get the certificate from the site
            checkCookies(getWebsite, response) # Check stored cookies
            checkMethods(getWebsite) # Check allowed HTTP methods
            checkCORS(getWebsite, response) # Check CORS configuration

            # Page structure and form security
            getPageInfo(getWebsite, response) # Get general page information
            checkForms(getWebsite, response) # Check forms on the page
            checkInsecureForms(getWebsite, response) # Check for insecure form actions
            checkPasswordAutocomplete(getWebsite, response) # Check password autocomplete settings
            checkAccessKey(getWebsite, response) # Check for exposed access keys

            # Page assets and metadata
            checkMixedContent(response) # Check for mixed HTTP and HTTPS content
            checkExternalScripts(getWebsite, response) # List external scripts
            checkSRI(getWebsite, response) # Check Subresource Integrity
            checkComments(getWebsite, response) # Check HTML comments
            getFaviconHash(getWebsite, response) # Hash the site favicon

            # Site discovery and exposed resources
            getRobots(getWebsite) # Get robots and sitemap
            checkDirectoryListing(getWebsite) # Check for exposed directory listings
            checkSensitiveFiles(getWebsite) # Check for exposed sensitive files
            checkSecurityTxt(getWebsite) # Check for security.txt
            getDNS(getWebsite) # Resolve the site DNS information
            findEmails(getWebsite, response) # Find email addresses in the page
            discoverSubdomains(getWebsite, response) # Find linked paths and subdomains

            # Technology and performance
            getWebTechnologies(getWebsite) # Get the web technologies. Area of improvement.
            checkPerformanceReport(response) # Generate the performance report
        
        finally:
            sys.stdout = original_stdout
            sys.stderr = original_stderr