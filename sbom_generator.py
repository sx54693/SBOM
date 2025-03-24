import os
import json
import pefile
import platform
import hashlib
from fastapi import FastAPI, UploadFile, File

app = FastAPI()

def secure_filename(filename):
    return os.path.basename(filename).replace(" ", "_")

def calculate_sha256(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            sha256.update(chunk)
    return sha256.hexdigest()

def extract_metadata(file_path):
    metadata = {
        "Software Name": os.path.basename(file_path),
        "Format": "CycloneDX",
        "Version": "N/A",
        "Generated On": "N/A",
        "Tool Used": "Syft",
        "Tool Version": "1.6",
        "Vendor": "N/A",
        "Compiler": "N/A",
        "Platform": platform.architecture()[0],
        "Digital Signature": "⚠️ Signature Check Not Available on Cloud"
    }

    if file_path.endswith(".exe"):
        try:
            pe = pefile.PE(file_path)

            # Compiler extraction
            if hasattr(pe, "OPTIONAL_HEADER"):
                major = pe.OPTIONAL_HEADER.MajorLinkerVersion
                minor = pe.OPTIONAL_HEADER.MinorLinkerVersion
                metadata["Compiler"] = f"Linker {major}.{minor}"

            # Vendor and version extraction
            if hasattr(pe, "FileInfo"):
                for file_info in pe.FileInfo:
                    if hasattr(file_info, "StringTable"):
                        for entry in file_info.StringTable:
                            for key, value in entry.entries.items():
                                k = key.decode(errors="ignore").strip()
                                v = value.decode(errors="ignore").strip()
                                if k == "CompanyName":
                                    metadata["Vendor"] = v or "N/A"
                                elif k == "ProductVersion":
                                    metadata["Version"] = v or "N/A"

        except Exception as e:
            print(f"⚠️ Metadata extraction issue: {e}")

    return metadata

@app.post("/generate-sbom/")
async def generate_sbom(file: UploadFile = File(...)):
    file_location = f"uploaded_apps/{secure_filename(file.filename)}"
    os.makedirs("uploaded_apps", exist_ok=True)
    
    with open(file_location, "wb") as buffer:
        buffer.write(await file.read())

    metadata = extract_metadata(file_location)

    components = [{
        "type": "application",
        "name": metadata["Software Name"],
        "version": metadata["Version"],
        "supplier": {"name": metadata["Vendor"]},
        "hashes": [{"alg": "SHA-256", "content": calculate_sha256(file_location)}],
        "licenses": [{"license": {"name": "Proprietary"}}]
    }]

    sbom_json = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {
            "timestamp": metadata["Generated On"],
            "component": {
                "name": metadata["Software Name"],
                "version": metadata["Version"],
                "type": "application"
            },
            "tools": [{"name": metadata["Tool Used"], "version": metadata["Tool Version"]}],
            "supplier": {"name": metadata["Vendor"]},
        },
        "components": components,
        "additionalProperties": {
            "Compiler": metadata["Compiler"],
            "Platform": metadata["Platform"],
            "Digital Signature": metadata["Digital Signature"]
        }
    }

    output_dir = "sbom_outputs"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, secure_filename(file.filename) + "_sbom.json")

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sbom_json, f, indent=4)

    return sbom_json

