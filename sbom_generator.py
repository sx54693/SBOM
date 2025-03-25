import os
import requests

API_URL = "https://your-render-api.onrender.com/generate-sbom"

def generate_sbom(file_path):
    """Generate SBOM by calling the Render-hosted API."""

    if not os.path.exists(file_path):
        print(f"❌ File not found: {file_path}")
        return None

    try:
        with open(file_path, "rb") as f:
            files = {"file": f}
            response = requests.post(API_URL, files=files)

        if response.status_code == 200:
            sbom_json = response.json()

            # Save the SBOM locally
            output_dir = "sbom_outputs"
            os.makedirs(output_dir, exist_ok=True)

            sbom_output_path = os.path.join(
                output_dir, os.path.basename(file_path) + "_sbom.json"
            )

            with open(sbom_output_path, "w", encoding="utf-8") as out_file:
                json.dump(sbom_json, out_file, indent=4)

            return sbom_output_path

        else:
            print(f"❌ SBOM API Error: {response.status_code} - {response.text}")
            return None

    except Exception as e:
        print(f"❌ Exception while calling SBOM API: {e}")
        return None
