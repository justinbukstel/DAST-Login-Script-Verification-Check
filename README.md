# DAST Login Script Verification Check

This tool can be used to verify that the last step in a Veracode login script is a verification step. It is best practice to have a verification step as your last step to confirm a logged in state. Without the verification step, a DAST scan may not have sufficient coverage due to invalid credentials, a change in the login sequence, etc. If no verification step is included, the scan may seem successfull when it might not be. 

The tool will output all your DAST analysis scans links that do not have a login script verification into a CSV. 

To run this script please follow these steps: 

1. Ensure you have your credentials saved in a credentials file (https://docs.veracode.com/r/c_api_credentials3)

2. Run ```
   pip install -r requirements.txt ```
3. run ```
python DastScriptCheck.py```
