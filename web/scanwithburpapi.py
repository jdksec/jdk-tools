import requests
import json
import sys
import time
import subprocess
from concurrent.futures import ThreadPoolExecutor

def check_scan_status(scan_url):
    response = requests.get(scan_url)
    if response.status_code == 200:
        scan_data = response.json()
        return scan_data.get('scan_status', '')
    return ''

log_file_path = 'scanlog.txt'

def scan_url(target, url, burp_proxy):
    try:
        hakrawler_cmd = f'echo {target} | hakrawler -d 4 | ~/go/bin/httpx -silent -http-proxy {burp_proxy}'
        output = subprocess.check_output(hakrawler_cmd, shell=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running hakrawler and httpx for {target}: {e}")

    config = {
        "scan_configurations": [
            {"name": "Crawl and Audit - jdk", "type": "NamedConfiguration"}
        ],
        "scope": {
            "include": [{"rule": target}],
            "type": "SimpleScope"
        },
        "urls": [target]
    }

    response = requests.post(url, json=config)

    location_header = response.headers.get('location', 'Header not found')
    scan_url = f'http://127.0.0.1:1337/v0.1/scan/{location_header}'
    log_message = f"Started scan for: {target}: {scan_url}"

    with open(log_file_path, 'a') as log_file:
        log_file.write(log_message + '\n')

    print(log_message)

    while True:
        time.sleep(30)
        status = check_scan_status(scan_url)
        if status == 'succeeded':
            log_message = f"Scan succeeded for: {target}"
            with open(log_file_path, 'a') as log_file:
                log_file.write(log_message + '\n')
            print(log_message)
            return
        elif status == 'paused':
            log_message = f"Scan paused for: {target}"
            with open(log_file_path, 'a') as log_file:
                log_file.write(log_message + '\n')
            print(log_message)
            return

targets = [line.strip() for line in sys.stdin]

if not targets:
    print("No URLs provided.")
    sys.exit(1)

url = 'http://127.0.0.1:1337/v0.1/scan'
burp_proxy = 'http://127.0.0.1:8080'

max_concurrent_scans = 6

with ThreadPoolExecutor(max_concurrent_scans) as executor:
    futures = []
    for target in targets:
        future = executor.submit(scan_url, target, url, burp_proxy)
        futures.append(future)

    for future in futures:
        future.result()
