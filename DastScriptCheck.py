from ratelimit import limits, sleep_and_retry
import requests
import csv
import json
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC

# Rate limit: 250 API requests per minute
@sleep_and_retry
@limits(calls=250, period=60)
def api_request(url, headers):
    response = requests.get(url, auth=RequestsAuthPluginVeracodeHMAC(), headers=headers)
    return response

# Function to get the most recent scan occurrence ids for a given analysis occurrence id
def get_most_recent_scan_occurrence_ids(analysis_id):
    url = f"https://api.veracode.com/was/configservice/v1/analysis_occurrences/{analysis_id}/scan_occurrences?page=0&size=1&sort=created_on,desc"
    headers = {"User-Agent": "Python HMAC"}
    response = api_request(url, headers)
    
    if response.status_code == 200:
        data = response.json()
        scan_occurrences = data.get("_embedded", {}).get("scan_occurrences", [])
        return [occurrence.get("scan_occurrence_id") for occurrence in scan_occurrences]
    else:
        print(f"Failed to retrieve scan occurrences for analysis_id {analysis_id}. Status code: {response.status_code}")
        return []

# Function to check if the last command in the script is a "verifyText" or "assertText"
def check_veracode_scan(scan_occurrence_id, writer):
    url = f"https://api.veracode.com/was/configservice/v1/scan_occurrences/{scan_occurrence_id}/configuration"
    headers = {"User-Agent": "Python-HMAC"}
    response = api_request(url, headers)

    if response.status_code != 200:
        print(f"Failed to retrieve data for scan occurrence ID {scan_occurrence_id}")
        return

    data = response.json()
    auth_config = data.get("auth_configuration", {}).get("authentications", {})
    form_auth = auth_config.get("FORM", {})

    if form_auth:
        script_body = form_auth.get("login_script_data", {}).get("script_body", "")
        if script_body:
            script_data = json.loads(script_body)
            commands = script_data.get("tests", [{}])[0].get("commands", [])

            if commands:
                last_command = commands[-1].get("command", "")
                
                if last_command not in ["verifyText", "assertText", "waitForElementPresent"]:
                    print(f"Invalid last command for scan occurrence ID {scan_occurrence_id}: {last_command}")
                    writer.writerow({
                        "url": f"https://web.analysiscenter.veracode.com/was/#/scanoccurrence/{scan_occurrence_id}/scandetails"
                    })

# Function to process scan occurrences
def process_scan_occurrences(latest_occurrences, writer):
    for occurrence in latest_occurrences:
        scan_occurrence_ids = get_most_recent_scan_occurrence_ids(occurrence)
        for scan_occurrence_id in scan_occurrence_ids:
            check_veracode_scan(scan_occurrence_id, writer)

# Define the URL of the Veracode API endpoint to get analyses and get the latest analysis occurrence
base_url = "https://api.veracode.com/was/configservice/v1/analyses"
headers = {"User-Agent": "Python HMAC"}

# Initialize an empty list to hold all web scan analysis occurrences
latest_web_scan_ids = []
page = 0
total_pages = 1

while page < total_pages:
    url = f"{base_url}?page={page}&size=500"
    response = api_request(url, headers)

    if response.status_code == 200:
        data = response.json()
        total_pages = data.get("page", {}).get("total_pages", 1)
        analyses = data.get("_embedded", {}).get("analyses", [])

        for analysis in analyses:
            if analysis.get("scan_type") == "WEB_SCAN":
                latest_occurrence = analysis.get("_links", {}).get("latest_occurrence", {}).get("href")
                if latest_occurrence:
                    latest_web_scan_ids.append(latest_occurrence.split('/')[-1])

        page += 1
    else:
        print(f"Failed to retrieve analyses. Status code: {response.status_code}")
        break

if latest_web_scan_ids:
    with open("invalid_scan_occurrences.csv", "w", newline='') as csvfile:
        fieldnames = ["url"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        process_scan_occurrences(latest_web_scan_ids, writer)
else:
    print("No web scan analysis occurrences found.")

















