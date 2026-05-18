"""
fix_splunk_upload.py (FIXED)
=====================
Run this to fix the Splunk lookup definitions.
The script now correctly targets specific file resources in the API.
"""

import requests
import getpass
import os
import xml.etree.ElementTree as ET
import urllib3
urllib3.disable_warnings()

# ── Config ─────────────────────────────────────────────────────
HOST     = 'localhost'
PORT     = 8089
USERNAME = 'Marah'
APP      = 'search'

LOOKUPS = [
    ('model1_weighted_risk_output.csv',  'model1_weighted_risk'),
    ('model2_zscore_anomalies.csv',       'model2_zscore_anomalies'),
    ('model3_ip_enrichment.csv',          'model3_ip_enrichment'),
    ('model4_new_ioc_predictions.csv',    'model4_new_ioc_predictions'),
]

BASE = f'https://{HOST}:{PORT}'

def login(password):
    resp = requests.post(
        f'{BASE}/services/auth/login',
        data={'username': USERNAME, 'password': password},
        verify=False, timeout=10
    )
    if resp.status_code != 200:
        print(f"Login failed: {resp.status_code}")
        return None
    root = ET.fromstring(resp.text)
    key = root.findtext('sessionKey')
    if key:
        print(f"Connected to Splunk as '{USERNAME}'")
        return {'Authorization': f'Splunk {key}'}
    return None

def upload_file(headers, local_path, splunk_filename):
    """Upload a CSV file to Splunk's lookup file storage."""
    url = f'{BASE}/servicesNS/{USERNAME}/{APP}/data/lookup-table-files/{splunk_filename}'

    with open(local_path, 'rb') as f:
        csv_data = f.read()

    # FIX: Use None for the filename in the tuple to prevent Python from sending it
    resp = requests.post(
        url,
        headers=headers,
        files={'eai:data': (None, csv_data, 'text/csv')},
        verify=False, timeout=30
    )
    
    if resp.status_code in (200, 201):
        print(f"  ✓ Uploaded file: {splunk_filename}")
        return True
    else:
        print(f"  ✗ File upload failed ({resp.status_code}): {resp.text[:150]}")
        return False

def create_definition(headers, lookup_name, splunk_filename):
    """Create or update a Splunk lookup definition."""
    # FIXED: The URL now includes the lookup name as a target
    url = f'{BASE}/servicesNS/{USERNAME}/{APP}/data/transforms/lookups/{lookup_name}'

    resp = requests.post(
        url,
        headers=headers,
        data={
            'name'     : lookup_name,
            'filename' : splunk_filename,
            'default_match': 'false',
            'case_sensitive_match': 'false',
        },
        verify=False, timeout=10
    )
    if resp.status_code in (200, 201):
        print(f"  ✓ Created definition: {lookup_name}")
        return True
    else:
        print(f"  ✗ Definition creation failed ({resp.status_code}): {resp.text[:150]}")
        return False

def verify_lookup(headers, lookup_name):
    resp = requests.post(
        f'{BASE}/services/search/jobs',
        headers=headers,
        data={
            'search': f'| inputlookup {lookup_name} | head 3',
            'output_mode': 'json',
            'earliest_time': '0',
            'latest_time': 'now',
        },
        verify=False, timeout=15
    )
    if resp.status_code not in (200, 201):
        return False

    import time
    sid = resp.json()['sid']
    for _ in range(10):
        time.sleep(2)
        job_info = requests.get(
            f'{BASE}/services/search/jobs/{sid}',
            headers=headers, params={'output_mode': 'json'},
            verify=False, timeout=10
        ).json()
        status = job_info['entry'][0]['content']['dispatchState']
        if status == 'DONE':
            break

    results = requests.get(
        f'{BASE}/services/search/jobs/{sid}/results',
        headers=headers, params={'output_mode': 'json', 'count': 3},
        verify=False, timeout=10
    ).json()
    return len(results.get('results', [])) > 0

def main():
    print("=" * 60)
    print("SPLUNK LOOKUP FIX SCRIPT")
    print("=" * 60)

    password = getpass.getpass("\nSplunk admin password: ")
    headers = login(password)
    if not headers:
        return

    print()
    success_count = 0
    for local_file, lookup_name in LOOKUPS:
        if not os.path.exists(local_file):
            print(f"\n! Skipping {lookup_name}: {local_file} not found locally.")
            continue
            
        splunk_filename = f'{lookup_name}.csv'
        print(f"\nProcessing: {lookup_name}")

        if upload_file(headers, local_file, splunk_filename):
            if create_definition(headers, lookup_name, splunk_filename):
                import time; time.sleep(1)
                if verify_lookup(headers, lookup_name):
                    print(f"  ✓ VERIFIED: Data is readable in Splunk")
                    success_count += 1
                else:
                    print(f"  ? Created but returned 0 rows (Check time range in Splunk)")

    print("\n" + "=" * 60)
    print(f"DONE: {success_count}/{len(LOOKUPS)} successful")
    print("=" * 60)

if __name__ == '__main__':
    main()