import os
import json
import pefile
import subprocess
import platform
import hashlib
import requests
from fastapi import FastAPI, UploadFile, File

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Initialize FastAPI app
app = FastAPI()

API_URL = "https://sbom.onrender.com"

def secure_filename(filename):
    """Sanitize filename to prevent issues."""
    return os.path.basename(filename).replace(" ", "_")

def extract_metadata(file_path):
    """Extract vendor, compiler, platform, and digital signature from an EXE file"""
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
    if platform.system() != "Windows":
        return "⚠️ Signature Check Not Available on Cloud"
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
    "components": [
        {
            "name": metadata["Software Name"],
            "type": "application",
            "version": metadata["Version"],
            "supplier": {"name": metadata["Vendor"]},
            "properties": [
                {"name": "Compiler", "value": metadata["Compiler"]},
                {"name": "Platform", "value": metadata["Platform"]},
                {"name": "Signature", "value": metadata["Digital Signature"]}
            ]
        }
    ]
}


        output_dir = os.path.join(BASE_DIR, "sbom_outputs")
        os.makedirs(output_dir, exist_ok=True)
     output_sbom = os.path.join(output_dir, secure_filename(file.filename) + ".json")


        # Save the SBOM JSON file
        with open(output_sbom, "w", encoding="utf-8") as f:
            json.dump(sbom_data, f, indent=2)

        print(f"✅ SBOM generated successfully: {output_sbom}")
        return output_sbom

    except Exception as e:
        print(f"❌ Exception in generate_sbom: {e}")
        return None


# ✅ **FastAPI Endpoint for SBOM Generation**
@app.post("/generate-sbom/")
async def generate_sbom_api(file: UploadFile = File(...)):
    """API Endpoint: Receives a file, generates SBOM, and returns the metadata."""
    file_location = f"uploaded_apps/{secure_filename(file.filename)}"
    
    # Save the uploaded file
    os.makedirs("uploaded_apps", exist_ok=True)
    with open(file_location, "wb") as buffer:
        buffer.write(await file.read())

    # Generate SBOM
    sbom_output = generate_sbom(file_location)

    if not sbom_output:
        return {"error": "SBOM generation failed"}

    # Read generated SBOM and return JSON response
    with open(sbom_output, "r", encoding="utf-8") as sbom_file:
        sbom_json = json.load(sbom_file)

    return sbom_json
