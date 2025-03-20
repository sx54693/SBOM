import requests

API_URL = "https://sbom.onrender.com"

# Open a test file and send it to the API
with open("testfile.exe", "rb") as file:
    response = requests.post(f"{API_URL}/generate-sbom", files={"file": file})

# Print response
print(response.status_code)
print(response.json())  # This should show the SBOM output file path
