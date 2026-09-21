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
    print(f"{RED}\n----------------------------------------\nThis tool should only be utilised on websites you are authorised to scan.\nScanning unauthorised websites may be illegal.\n----------------------------------------{RESET}")
    
    agreeToPrivacyInput = input('\nAgree to above? (y/n):')
    
    if (agreeToPrivacyInput == 'y'):
        return
    else: # If user doesn't type anything but y
        print(f"{RED}You need to agree to the above before you can use this tool{RESET}")
        exit() # Quit
        
# Handle clearing the logs or scanning a website
def startOptions():
    print('\nPlease choose an option:\n1 - Scan a website\n2 - Clear log files')
    whichOption = input('Enter: ')
    
    if (whichOption == '1'):
        return # Return to where the function was called from which carries on with the natural flow of the program
        
    if (whichOption == '2'):
        print(f"{RED}Clearing log files{RESET}")
        shutil.rmtree("logs") # Remove the logs folder
        
        folder = Path(__file__).parent / "logs" # Grab the logs folder
        
        # Check to see if it has been deleted or not
        if folder.is_dir():
            print(f"{RED}Folder could not be deleted{RESET}")
        else:
            print(f"{GREEN}Folder deleted successfully{RESET}")
            
        exit() # Exit regardless
        
    else: # Exit if 1 or 2 was not chosen
        print(f"{RED}You need to choose an option. Exiting...{RESET}")
        exit() # Quit
        
#  Handle getting the website the user wants to scan
def grabWebsite():
    print(f"{GRAY}Getting the website{RESET}")
    extensions = ['.com', '.co.uk', '.org', '.net', '.io', 'https://', 'http://'] # Site extensions
    
    print(f"{GRAY}Initialising getting the website{RESET}")
    
    getWebsite = input('Enter the URL of the website you want to scan: ')
    print(f"{GRAY}{getWebsite}{RESET}")
    
    if not getWebsite: # If user doesn't enter anything
        print(f"{RED}Input is empty. Exiting...{RESET}")
        exit()

    if not any(extension in getWebsite for extension in extensions): # If domain extension or https/http is missing
        print(f"{RED}Input does not contain domain extension and/or https/http Exiting...{RESET}")
        exit()

    return getWebsite # Returning the stored website allows the program to pass the inputted website around without declaring it globally

# Check if the website is even valid
def checkValidWebsite(getWebsite):
    print(f"{GRAY}Checking if website is valid{RESET}")
    
    try:
        response = requests.get(getWebsite, timeout=10) # Send a request to the site with a 10 sec timeout

        print(f"{GRAY}Website status: {response.status_code}{RESET}") # Display response code

        if response.ok: # If response is ok
            print(f"{GREEN}Website is reachable.{RESET}")
        else:
            print(f"{RED}Website returned an error. Exiting...{RESET}")
            exit() # Quit if no response

        return response

    except requests.RequestException:
        print(f"{RED}Website could not be reached. Exiting...{RESET}")
        exit()

# Scan site headers
def headerScan(getWebsite, response):
    print(f"{GRAY}Getting web headers{RESET}")
    
    # Store common headers found on a website.
    # This isn't necessarily a problem if they are missing, but just good to know. 
    security_headers = [
        # Core security headers
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Permissions-Policy",

        # Cross origin isolation/protection
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Resource-Policy",
        "Cross-Origin-Embedder-Policy",

        # Caching
        "Cache-Control",
        "Pragma",

        # Browser/download protections
        "Content-Disposition",

        # CSP related reporting
        "Reporting-Endpoints",
        "NEL",

        # Certificate/transport-related
        "Expect-CT",

        # Legacy headers
        "X-XSS-Protection",
        "X-Permitted-Cross-Domain-Policies",

        # Microsoft specific
        "X-Download-Options"
    ]

    print(f"{GRAY}Scanning {getWebsite} {RESET}")
    
    headers = response.headers # Check if headers are found
    
    if headers: # If headers are found
        print(f"{GREEN}Website headers found{RESET}")
        
        # Loop round the headers to see which have been found
        for header in security_headers:
            if header in response.headers: # Check the response of each header
                print(f"{GRAY}{header}:{RESET}" f"{GREEN}PRESENT{RESET}")
            else:
                print(f"{GRAY}{header}:{RESET}" f"{ORANGE}MISSING{RESET}")
    else:
        print(f"{RED}Could not get website headers despite website being reachable{RESET}")
        # Don't wanna quit it here so we leave this blank so the program can continue
        
# Get the web technologies used on the site
# This is a WIP and doesn't display a lot right now
# Use a library called webtech
def getWebTechnologies(getWebsite):
    print(f"{GRAY}Getting web technologies{RESET}")
    
    wt = webtech.WebTech(options={'json': True})

    try:
        result = wt.start_from_url(getWebsite) # Scan the website using webtech for technologies
        print(f"{GREEN}Web technologies found{RESET}")
        
        technologies = result.get('tech', [])
        
        for item in technologies: # Loop the found items in stored technologies
            name = item.get('name', 'Unknown')
            
            print(f"{GRAY}- {name}{RESET}") # Print found technologies
            
    except Exception as e: # If no technologies found
        print(f"{ORANGE}No web technologies found: {e}{RESET}")

# Get site certifications
def getCert(getWebsite):
    parsed = urlparse(getWebsite) # Parse the website URL

    if parsed.scheme != "https": # Check if site uses https
        print(f"{GRAY}TLS certificate: Not applicable (HTTP){RESET}")
        return

    hostname = parsed.hostname # Get the website hostname

    context = ssl.create_default_context() # Create a secure SSL context

    # Connect to the website
    with socket.create_connection((hostname, 443), timeout=10) as sock:

        # Create a secure TLS connection
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:

            certificate = ssock.getpeercert() # Get the website's certificate

            # Show the TLS version and cipher used
            print(f"{GRAY}TLS Version: {ssock.version()}{RESET}")
            print(f"{GRAY}Cipher: {ssock.cipher()[0]}{RESET}")

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
            print(f"{GRAY}Issuer: {issuer}{RESET}")
            print(f"{GRAY}Valid from: {certificate['notBefore']}{RESET}")
            print(f"{GRAY}Valid until: {certificate['notAfter']}{RESET}")
            print(f"{GRAY}Subject: {subject}{RESET}")

# Get robots.txt and sitemap.xml
def getRobots(getWebsite):
    print(f"{GRAY}Getting robots and sitemap{RESET}")
    
    # Get the two files
    robots = requests.get(f"{getWebsite}/robots.txt", timeout=10)
    sitemap = requests.get(f"{getWebsite}/sitemap.xml", timeout=10)
    
    if robots.status_code == 200: # If robots is found
        print(f"{GREEN}robots.txt found{RESET}")
    else:
        print(f"{ORANGE}robots.txt not found{RESET}")

    if sitemap.status_code == 200: # If sitemap is found
        print(f"{GREEN}sitemap.xml found{RESET}")
    else:
        print(f"{ORANGE}sitemap.xml not found{RESET}")

# Check if any cookies are found on the site
def checkCookies(response):
    print(f"{GRAY}Getting website cookies{RESET}")
    
    cookies = response.cookies # Get the cookies

    if not cookies: # If no cookies are found
        print(f"{GRAY}No cookies found{RESET}")
        return

    for cookie in cookies: # Loop the found cookies
        print(f"{GRAY}Cookie: {cookie.name}{RESET}")

        if cookie.secure:
            print(f"{GREEN}Secure: Yes{RESET}")
        else:
            print(f"{RED}Secure: No{RESET}")

        if cookie.has_nonstandard_attr("HttpOnly"):
            print(f"{GREEN}HttpOnly: Yes{RESET}")
        else:
            print(f"{RED}HttpOnly: No{RESET}")

def checkMethods(getWebsite):
    print(f"{GRAY}Checking for any allowed methods{RESET}")
    
    response = requests.options(getWebsite, timeout=10)

    methods = response.headers.get("Allow")

    if methods:
        print(f"{GRAY}Allowed methods: {methods}{RESET}")
    else:
        print(f"{GREEN}Allowed methods not disclosed{RESET}")
        
def checkCORS(response):
    cors = response.headers.get("Access-Control-Allow-Origin")

    if cors:
        print(f"{GRAY}CORS: {cors}{RESET}")

        if cors == "*":
            print(f"{ORANGE}CORS allows all origins{RESET}")
        else:
            print(f"{GREEN}CORS origin restricted{RESET}")
    else:
        print(f"{GRAY}CORS: Not configured{RESET}")

def getPageInfo(response):
    print(f"{GRAY}Getting page info{RESET}")
    
    soup = BeautifulSoup(response.text, "html.parser")

    title = soup.title.string.strip() if soup.title else "No title"
    content_type = response.headers.get("Content-Type", "Unknown")
    page_size = len(response.content)

    print(f"{GRAY}Page title: {title}{RESET}")
    print(f"{GRAY}Content-Type: {content_type}{RESET}")
    print(f"{GRAY}Page size: {page_size} bytes{RESET}")
    
def checkForms(getWebsite, response):
    print(f"{GRAY}Getting forms on the site{RESET}")
    
    soup = BeautifulSoup(response.text, "html.parser")

    forms = soup.find_all("form")

    print(f"{GRAY}Forms found: {len(forms)}{RESET}")

    for form in forms:
        action = form.get("action", "")
        method = form.get("method", "GET").upper()

        action_url = urljoin(getWebsite, action)

        print(f"{GRAY}Form action: {action_url}{RESET}")
        print(f"{GRAY}Method: {method}{RESET}")

        password = form.find("input", {"type": "password"})

        if password:
            if action_url.startswith("http://"):
                print(f"{RED}Password form submits over HTTP.{RESET}")
            else:
                print(f"{GREEN}Password form submits over HTTPS.{RESET}")
                
def checkAccessKey(response):
    print(f"{GRAY}Checking leaked access key{RESET}")
    
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

    for name in names:
        access_key = soup.find("input", {"name": name})

        if access_key and access_key.get("value"):
            print(f"{RED}The value '{name}' in a form is exposed{RESET}")
            
def checkMixedContent(response):
    print(f"{GRAY}Checking mixed content{RESET}")
    
    soup = BeautifulSoup(response.text, "html.parser")

    found = False

    for tag in soup.find_all(["script", "img", "link", "iframe"]):
        url = tag.get("src") or tag.get("href")

        if url and url.startswith("http://"):
            print(f"{RED}Mixed content: {url}{RESET}")
            found = True

    if not found:
        print(f"{GREEN}No mixed content found. Site does not load resources over plain HTTP{RESET}")
        
def checkExternalScripts(response):
    print(f"{GRAY}Checking external scripts{RESET}")
    
    soup = BeautifulSoup(response.text, "html.parser")

    for script in soup.find_all("script"):
        src = script.get("src")

        if src:
            print(f"{ORANGE}Script: {src}{RESET}")
            
def checkSRI(response):
    print(f"{GRAY}Checking SRI{RESET}")
    
    soup = BeautifulSoup(response.text, "html.parser")

    found = False

    for tag in soup.find_all(["script", "link"]):
        url = tag.get("src") or tag.get("href")

        if url and url.startswith("http"):
            found = True

            if tag.get("integrity"):
                print(f"{GREEN}SRI: PRESENT - {url}{RESET}")
            else:
                print(f"{ORANGE}SRI missing on - {url}{RESET}")
                
    if not found:
        print(f"{GRAY}No external resources found.{RESET}")
        
def checkComments(response):
    print(f"{GRAY}Checking any long comments{RESET}")
    
    soup = BeautifulSoup(response.text, "html.parser")

    comments = soup.find_all(string=lambda text: isinstance(text, Comment))

    found = False

    for comment in comments:
        text = comment.strip()

        if len(text) < 5:
            continue

        print(f"{ORANGE}Comment: {text}{RESET}")
        found = True

    if not found:
        print(f"{GREEN}No useful comments found.{RESET}")
        
def checkDirectoryListing(getWebsite):
    print(f"{GRAY}Checking directory listings{RESET}")
    
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
            print(f"{RED}Directory listing exposed: {path}{RESET}")
        else:
            print(f"{GRAY}No directory listing: {path}{RESET}")
            
def checkSensitiveFiles(getWebsite):
    print(f"{GRAY}Checking sensitive files{RESET}")
    
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
            print(f"{ORANGE}{file}: FOUND{RESET}")
            print(f"{GRAY}Location: {url}{RESET}")
        elif response.status_code == 404:
            print(f"{GREEN}{file}: Not found{RESET}")
        else:
            print(f"{GRAY}{file}: HTTP {response.status_code}{RESET}")

def getDNS(getWebsite):
    print(f"{GRAY}Checking the DNS{RESET}")
    
    hostname = urlparse(getWebsite).hostname

    try:
        ip = socket.gethostbyname(hostname)

        print(f"{GRAY}IP Address: {ip}{RESET}")

    except socket.gaierror:
        print(f"{RED}Could not resolve hostname.{RESET}")
        
def findEmails(response):
    print(f"{GRAY}Finding emails{RESET}")
    
    emails = re.findall(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        response.text
    )

    emails = set(emails)

    if emails:
        emailCount = len(emails)
        print(f"{GRAY}Found {emailCount} emails{RESET}")

        sorted_emails = sorted(emails)

        for i, email in enumerate(sorted_emails):
            if i < 10:
                print(f"{ORANGE}Email found: {email}{RESET}")
            else:
                if hasattr(sys.stdout, "log_file"):
                    sys.stdout.log_file.write(f"Email found: {email}\n")
            
        if emailCount > 10:
            remaining = emailCount - 10
            print(f"{GRAY}...and {remaining} more found (check log.txt for full list){RESET}")
            
    else:
        print(f"{GREEN}No email addresses found.{RESET}")

def checkInsecureForms(response):
    print(f"{GRAY}Checking insecure forms{RESET}")
    
    soup = BeautifulSoup(response.text, "html.parser")

    found = False

    for form in soup.find_all("form"):
        action = form.get("action", "")

        if action.startswith("http://"):
            print(f"{RED}Insecure form: {action}{RESET}")
            found = True

    if not found:
        print(f"{GREEN}No insecure forms found.{RESET}")
        
def checkSecurityTxt(getWebsite):
    print(f"{GRAY}Checking security.txt{RESET}")
    
    url = getWebsite.rstrip("/") + "/.well-known/security.txt"

    response = requests.get(url, timeout=10)

    if response.status_code == 200:
        print(f"{ORANGE}security.txt found{RESET}")
        print(f"{ORANGE}Location: {url}{RESET}")
    elif response.status_code == 404:
        print(f"{GREEN}security.txt not found{RESET}")
    else:
        print(f"{GRAY}security.txt: HTTP {response.status_code}{RESET}")

def checkPasswordAutocomplete(response):
    print(f"{GRAY}Checking if password fields autocomplete{RESET}")
    
    soup = BeautifulSoup(response.text, "html.parser")

    found = False

    for password in soup.find_all("input", {"type": "password"}):
        found = True
        autocomplete = password.get("autocomplete")

        if autocomplete == "off":
            print(f"{GREEN}Password field: autocomplete=off{RESET}")
        elif autocomplete:
            print(f"{ORANGE}Password field: autocomplete={autocomplete}{RESET}")
        else:
            print(f"{GRAY}Password field: autocomplete not specified{RESET}")

    if not found:
        print(f"{GREEN}No password autocomplete fields found{RESET}")

def getFaviconHash(response):
    print(f"{GRAY}Checking and hashing favicon for infrastructure fingerprinting...{RESET}")
    
    soup = BeautifulSoup(response.text, "html.parser")
    favicon_url = None

    for link in soup.find_all("link"):
        rel = link.get("rel", [])
        if any(r in rel for r in ["icon", "shortcut icon", "apple-touch-icon"]):
            favicon_url = link.get("href")
            break

    if not favicon_url:
        favicon_url = "/favicon.ico"

    full_favicon_url = urljoin(favicon_url)

    try:
        fav_response = requests.get(full_favicon_url, timeout=10)
        if fav_response.status_code == 200:
            favicon_base64 = codecs.encode(fav_response.content, "base64")
            
            hash_value = mmh3.hash(favicon_base64)
            
            print(f"{GRAY}Favicon found at: {full_favicon_url}{RESET}")
            print(f"{GRAY}Favicon MurmurHash3: {ORANGE}{hash_value}{RESET}")
            
            shodan_url = f"https://www.shodan.io/search?query=http.favicon.hash%3A{hash_value}"
            print(f"{GRAY}Shodan Search Link. You need to be logged into Shodan to use this feature and it may return no results: {ORANGE}{shodan_url}{RESET}")
        else:
            print(f"{ORANGE}Favicon could not be retrieved (HTTP {fav_response.status_code}){RESET}")
    except Exception as e:
        print(f"{ORANGE}Error retrieving favicon: {e}{RESET}")


def checkPerformanceReport(response):
    print(f"{GRAY}Generating performance report{RESET}")
    
    elapsed_time_ms = response.elapsed.total_seconds() * 1000
    
    content_size_bytes = len(response.content)
    content_size_kb = content_size_bytes / 1024
    
    content_encoding = response.headers.get("Content-Encoding", "None")
    
    print(f"{GRAY}Performance and speed analysis:{RESET}")
    print(f"{GRAY}- Response Time (Latency): {GREEN}{elapsed_time_ms:.2f} ms{RESET}")
    print(f"{GRAY}- Main Page Size: {GREEN}{content_size_kb:.2f} KB{RESET}")
    
    if content_encoding != "None":
        print(f"{GRAY}- Text Compression: {GREEN}Enabled ({content_encoding}){RESET}")
    else:
        print(f"{GRAY}- Text Compression: {ORANGE}Disabled (Missing Content-Encoding){RESET}")

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
            startOptions()
            agreeToPrivacy() # Check if user agrees to not scanning random targets
            getWebsite = grabWebsite() # Grab the website the user wants to scan but only if they agree above. Setup variable here first so it can be passed on without global initalisation.
            response = checkValidWebsite(getWebsite) # Check if the website is valid
            headerScan(getWebsite, response) # Get the headers from the site
            getWebTechnologies(getWebsite) # Get the web technologies. Area of improvement.
            getCert(getWebsite) # Get the certificate from the site
            getRobots(getWebsite) # Get robots and sitemap
            checkCookies(getWebsite, response) # Check stored cookies
            checkMethods(getWebsite)
            checkCORS(getWebsite, response)
            getPageInfo(getWebsite, response)
            checkForms(getWebsite, response)
            checkAccessKey(getWebsite, response)
            checkMixedContent(response)
            checkExternalScripts(getWebsite, response)
            checkSRI(getWebsite, response)
            checkComments(getWebsite, response)
            checkDirectoryListing(getWebsite)
            checkSensitiveFiles(getWebsite)
            getDNS(getWebsite)
            findEmails(getWebsite, response)
            checkInsecureForms(getWebsite, response)
            checkSecurityTxt(getWebsite)
            checkPasswordAutocomplete(getWebsite, response)
            getFaviconHash(getWebsite, response)
            checkPerformanceReport(response)
        
        finally:
            sys.stdout = original_stdout
            sys.stderr = original_stderr