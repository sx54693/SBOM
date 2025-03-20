import os
import json
import pefile
import subprocess
import platform
import hashlib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def secure_filename(filename):
    """Sanitize filename to prevent issues."""
    return os.path.basename(filename).replace(" ", "_")

def extract_metadata(file_path):
    """Extract vendor, compiler, platform, digital signature from an EXE file"""
    metadata = {
        "Software Name": os.path.basename(file_path),
        "Format": "CycloneDX",
        "Version": "Unknown",
        "Generated On": "Unknown",
        "Tool Used": "Syft",
        "Tool Version": "Unknown",
        "Vendor": "Unknown",
        "Compiler": "Unknown",
        "Platform": platform.architecture()[0],
        "Digital Signature": "Not Available"
    }

    if file_path.endswith(".exe"):
        try:
            pe = pefile.PE(file_path)
            
            # Extract Compiler Version
            if hasattr(pe, "OPTIONAL_HEADER"):
                metadata["Compiler"] = f"Linker {pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}"

            # Extract Vendor
            if hasattr(pe, "FileInfo"):
                for file_info in pe.FileInfo:
                    if hasattr(file_info, "StringTable"):
                        for entry in file_info.StringTable:
                            for key, value in entry.entries.items():
                                key_decoded = key.decode(errors="ignore").strip()
                                value_decoded = value.decode(errors="ignore").strip()
                                if key_decoded == "CompanyName" and value_decoded:
                                    metadata["Vendor"] = value_decoded

            # Extract Digital Signature
            metadata["Digital Signature"] = check_digital_signature(file_path)

        except Exception as e:
            print(f"❌ Error extracting metadata: {e}")

    return metadata

def check_digital_signature(file_path):
    """Checks if an EXE file has a digital signature."""
    try:
        result = subprocess.run(["signtool", "verify", "/pa", file_path], capture_output=True, text=True)
        if "Successfully verified" in result.stdout:
            return "✅ Signed"
        return "❌ Not Signed"
    except Exception:
        return "⚠️ Signature Check Tool Not Found"

def generate_sbom(file_path):
    """Generates an SBOM for the given file"""
    try:
        if not os.path.exists(file_path):
            print(f"❌ Error: File {file_path} not found.")
            return None

        metadata = extract_metadata(file_path)
        sbom_data = {
            "metadata": metadata,
            "components": []
        }

        output_dir = os.path.join(BASE_DIR, "sbom_outputs")
        os.makedirs(output_dir, exist_ok=True)
        output_sbom = os.path.join(output_dir, secure_filename(file_path) + ".json")

        with open(output_sbom, "w", encoding="utf-8") as f:
            json.dump(sbom_data, f, indent=2)

        print(f"✅ SBOM generated successfully: {output_sbom}")
        return output_sbom

    except Exception as e:
        print(f"❌ Exception in generate_sbom: {e}")
        return None
  API_URL = "https://sbom.onrender.com"
def generate_sbom(file):
    """Calls the FastAPI backend to generate SBOM."""
    try:
        response = requests.post(f"{API_URL}/generate-sbom", files={"file": file})
        response_json = response.json()

        if "metadata" not in response_json:
            st.error("⚠️ SBOM API returned invalid response.")
            return None

        return response_json
    except Exception as e:
        st.error(f"❌ Error calling API: {str(e)}")
        return None


        # ✅ Write SBOM JSON to file
        with open(sbom_file_path, "w", encoding="utf-8") as f:
            json.dump(sbom_data, f, indent=4)

        print(f"✅ SBOM successfully created: {sbom_file_path}")  # ✅ Debugging
        return sbom_file_path  # ✅ Return file path instead of JSON data

    except Exception as e:
        print(f"❌ Error generating SBOM: {str(e)}")
        return None  # Return None if SBOM fails
        API_URL = "https://sbom.onrender.com"



