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

# Function to get the most recent scan_occurrence_ids for a given analysis_id
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

# Function to process scan occurrences and check if the last command is a "verifyText" or "assertText"
def process_scan_occurrences(analysis_occurrence_ids, total_pages, writer):
    processed_ids = set()  # To store processed scan_occurrence_ids
    for analysis_occurrence_id in analysis_occurrence_ids:
        for page in range(total_pages):
            scan_occurrence_ids = get_most_recent_scan_occurrence_ids(analysis_occurrence_id)
            for scan_occurrence_id in scan_occurrence_ids:
                if scan_occurrence_id not in processed_ids:
                    check_veracode_scan(scan_occurrence_id, writer)
                    processed_ids.add(scan_occurrence_id)

# Function to check if the last command in the script is a "verifyText" or "assertText"
def check_veracode_scan(scan_occurrence_id, writer):
    # Define the API endpoint
    url = f"https://api.veracode.com/was/configservice/v1/scan_occurrences/{scan_occurrence_id}/configuration"
    headers = {"User-Agent": "Python-HMAC"}
    response = api_request(url, headers)

    # Check if the request was successful
    if response.status_code != 200:
        print(f"Failed to retrieve data for scan occurrence ID {scan_occurrence_id}")
        return

    # Parse the JSON response
    data = response.json()

    # Check if the authentication type is FORM
    auth_config = data.get("auth_configuration", {}).get("authentications", {})
    form_auth = auth_config.get("FORM", {})

    if form_auth:
        # Parse the script body
        script_body = form_auth.get("login_script_data", {}).get("script_body", "")
        if script_body:
            script_data = json.loads(script_body)
            commands = script_data.get("tests", [{}])[0].get("commands", [])

            if commands:
                last_command = commands[-1].get("command", "")
                
                # Check if the last command is verifyText or assertText
                if last_command not in ["verifyText", "assertText", "waitForElementPresent"]:
                    print(f"Invalid last command for scan occurrence ID {scan_occurrence_id}: {last_command}")
                    
                    # Write the scan_occurrence_id to a CSV file
                    writer.writerow({
                        "url": f"https://web.analysiscenter.veracode.com/was/#/scanoccurrence/{scan_occurrence_id}/scandetails"
                    })

# Define the URL of the Veracode API endpoint to get analysis occurrences
url = "https://api.veracode.com/was/configservice/v1/analysis_occurrences?page=0&size=500"
headers = {"User-Agent": "Python HMAC"}

# Make the GET request to the Veracode API
response = api_request(url, headers)

if response.status_code == 200:
    data = response.json()
    total_pages = data.get("page", {}).get("total_pages", 1)
    analysis_occurrences = data.get("_embedded", {}).get("analysis_occurrences", [])
    
    # Filter and group analysis occurrences by analysis_id
    analysis_occurrences_by_id = {}
    for occurrence in analysis_occurrences:
        if occurrence.get("scan_type") == "WEB_SCAN":
            analysis_id = occurrence.get("analysis_id")
            if analysis_id in analysis_occurrences_by_id:
                if occurrence.get("actual_end_date") > analysis_occurrences_by_id[analysis_id].get("actual_end_date"):
                    analysis_occurrences_by_id[analysis_id] = occurrence
            else:
                analysis_occurrences_by_id[analysis_id] = occurrence
    
    # Extract the latest analysis_occurrence_id for each analysis_id
    latest_web_scan_ids = [occurrence["analysis_occurrence_id"] for occurrence in analysis_occurrences_by_id.values()]
    
    if latest_web_scan_ids:
        # Open the CSV file in write mode to overwrite it if it already exists
        with open("invalid_scan_occurrences.csv", "w", newline='') as csvfile:
            fieldnames = ["url"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            process_scan_occurrences(latest_web_scan_ids, total_pages, writer)
    else:
        print("No WEB_SCAN analysis occurrences found.")
else:
    print("Failed to retrieve analysis occurrences. Status code:", response.status_code)
















