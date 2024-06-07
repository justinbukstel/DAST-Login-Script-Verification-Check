# DAST-Login-Script-Verification-Check

Veracode Login Script Verifier
This script can be utilized to verify that the last step in your Veracode Login Script contains a verification command. Without a verification step as the last step in your script, there is a risk for your DAST scan not getting sufficient coverage. If there is no verification command, the script will add URLs to those scans so a user can look into adding those steps.

If you do have URLs in that list and need to update your script, here is a list of best practices when it comes to login scripts: Veracode Selenium Script Best Practices

Prerequisites

Python installed
API credentials saved to a credentials file
How to Use

bash
Copy code
pip install -r requirements.txt
bash
Copy code
python DastScriptCheck.py
