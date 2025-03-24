import os
import json
import pefile
import subprocess
import platform
import hashlib
from fastapi import FastAPI, UploadFile, File

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Initialize FastAPI app
app = FastAPI()

def secure_filename(filename):
    """Sanitize filename."""
    return os.path.basename(filename).replace(" ", "_")

def extract_metadata(file_path):
    """Extract metadata from an EXE file."""
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

            if hasattr(pe, "OPTIONAL_HEADER"):
                metadata["Compiler"] = f"Linker {pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}"

            if hasattr(pe, "FileInfo"):
                for file_info in pe.FileInfo:
                    if hasattr(file_info, "StringTable"):
                        for entry in file_info.StringTable:
                            for key, value in entry.entries.items():
                                key_decoded = key.decode(errors="ignore").strip()
                                value_decoded = value.decode(errors="ignore").strip()
                                if key_decoded == "CompanyName" and value_decoded:
                                    metadata["Vendor"] = value_decoded

            metadata["Digital Signature"] = check_digital_signature(file_path)

        except Exception as e:
            print(f"❌ Metadata extraction error: {e}")

    return metadata

def check_digital_signature(file_path):
    """Check digital signature."""
    try:
        result = subprocess.run(["signtool", "verify", "/pa", file_path], capture_output=True, text=True)
        if "Successfully verified" in result.stdout:
            return "✅ Signed"
        return "❌ Not Signed"
    except Exception:
        return "⚠️ Signature Check Tool Not Found"

def generate_sbom(file_path):
    """Generate SBOM with real components using Syft."""
    try:
        if not os.path.exists(file_path):
            return None

        output_dir = os.path.join(BASE_DIR, "sbom_outputs")
        os.makedirs(output_dir, exist_ok=True)
        output_sbom = os.path.join(output_dir, secure_filename(file_path) + ".json")

        # Generate SBOM using Syft
        syft_cmd = ["syft", file_path, "-o", "cyclonedx-json"]
        syft_result = subprocess.run(syft_cmd, capture_output=True, text=True)

        if syft_result.returncode != 0:
            print(f"❌ Syft Error: {syft_result.stderr}")
            return None

        sbom_data = json.loads(syft_result.stdout)

        # Extract and add metadata
        metadata = extract_metadata(file_path)
        sbom_data["metadata"] = metadata

        with open(output_sbom, "w", encoding="utf-8") as f:
            json.dump(sbom_data, f, indent=2)

        print(f"✅ SBOM generated successfully: {output_sbom}")
        return output_sbom

    except Exception as e:
        print(f"❌ Exception in generate_sbom: {e}")
        return None

@app.post("/generate-sbom/")
async def generate_sbom_api(file: UploadFile = File(...)):
    file_location = f"uploaded_apps/{secure_filename(file.filename)}"

    os.makedirs("uploaded_apps", exist_ok=True)
    with open(file_location, "wb") as buffer:
        buffer.write(await file.read())

    sbom_output = generate_sbom(file_location)

    if not sbom_output:
        return {"error": "SBOM generation failed"}

    with open(sbom_output, "r", encoding="utf-8") as sbom_file:
        sbom_json = json.load(sbom_file)

    return sbom_json
