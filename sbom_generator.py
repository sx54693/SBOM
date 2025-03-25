import os
import json
import pefile
import platform
import hashlib
import subprocess
from datetime import datetime
from fastapi import FastAPI, UploadFile, File

app = FastAPI()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def secure_filename(filename):
    return os.path.basename(filename).replace(" ", "_")

def calculate_sha256(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def extract_metadata(file_path):
    metadata = {
        "Software Name": os.path.basename(file_path),
        "Format": "CycloneDX",
        "Version": "Unknown",
        "Generated On": datetime.utcnow().isoformat() + "Z",
        "Tool Used": "Syft",
        "Tool Version": "1.2.3",  # Set your actual Syft version here
        "Vendor": "Unknown",
        "Compiler": "Unknown",
        "Platform": platform.architecture()[0],
        "Digital Signature": "Not Supported on Render/Linux"
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
                                key_decoded = key.decode(errors="ignore").strip().lower()
                                value_decoded = value.decode(errors="ignore").strip()
                                if key_decoded == "companyname":
                                    metadata["Vendor"] = value_decoded or "Unknown"
        except Exception as e:
            metadata["Vendor"] = f"Error: {e}"

    return metadata

@app.post("/generate-sbom/")
async def generate_sbom(file: UploadFile = File(...)):
    file_path = f"/tmp/{secure_filename(file.filename)}"

    with open(file_path, "wb") as buffer:
        buffer.write(await file.read())

    try:
        command = ["syft", file_path, "-o", "cyclonedx-json"]
        result = subprocess.run(command, capture_output=True, text=True)

        if result.returncode != 0:
            return {"error": f"Syft Error: {result.stderr}"}

        sbom_json = json.loads(result.stdout)
        metadata = extract_metadata(file_path)

        # Properly enrich SBOM with additional metadata
        sbom_json["metadata"]["timestamp"] = metadata["Generated On"]
        sbom_json["metadata"]["component"] = {
            "name": metadata["Software Name"],
            "type": "application"
        }
        sbom_json["metadata"]["tools"] = [{
            "name": metadata["Tool Used"],
            "version": metadata["Tool Version"]
        }]
        sbom_json["metadata"]["supplier"] = {"name": metadata["Vendor"]}

        sbom_json["additionalProperties"] = {
            "Compiler": metadata["Compiler"],
            "Platform": metadata["Platform"],
            "Digital Signature": metadata["Digital Signature"],
            "SHA256": calculate_sha256(file_path)
        }

        output_dir = os.path.join(BASE_DIR, "sbom_outputs")
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, secure_filename(file_path) + "_sbom.json")

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(sbom_json, f, indent=2)

        return sbom_json  # Direct JSON response for Render API

    except Exception as e:
        return {"error": f"Error generating SBOM: {e}"}

