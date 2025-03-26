import os
import json
import pefile
import platform
import hashlib
import subprocess
from fastapi import FastAPI, UploadFile, File
from datetime import datetime

app = FastAPI()

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
        "Tool Version": "1.0",
        "Vendor": "Unknown",
        "Compiler": "Unknown",
        "Platform": platform.architecture()[0],
        "Digital Signature": "Not Available on Cloud"
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
                                if key_decoded == "CompanyName":
                                    metadata["Vendor"] = value_decoded
        except:
            pass

    return metadata

@app.post("/generate-sbom/")
async def generate_sbom(file: UploadFile = File(...)):
    file_path = f"/tmp/{secure_filename(file.filename)}"
    with open(file_path, "wb") as buffer:
        buffer.write(await file.read())

    try:
        syft_command = ["syft", file_path, "-o", "cyclonedx-json"]
        result = subprocess.run(syft_command, capture_output=True, text=True)

        if result.returncode != 0:
            return {"error": f"Syft failed: {result.stderr}"}

        sbom_json = json.loads(result.stdout)
        metadata = extract_metadata(file_path)

        # Enrich the SBOM JSON directly for the API response
        sbom_json["metadata"]["timestamp"] = metadata["Generated On"]
        sbom_json["metadata"]["component"]["name"] = metadata["Software Name"]
        sbom_json["metadata"]["supplier"] = {"name": metadata["Vendor"]}
        sbom_json["metadata"]["tools"] = [{"name": metadata["Tool Used"], "version": metadata["Tool Version"]}]

        # Include additional properties
        sbom_json["additionalProperties"] = {
            "Compiler": metadata["Compiler"],
            "Platform": metadata["Platform"],
            "Digital Signature": metadata["Digital Signature"],
            "SHA256": calculate_sha256(file_path)
        }

        # Return enriched SBOM JSON directly as response
        return sbom_json

    except Exception as e:
        return {"error": str(e)}
        from fastapi import FastAPI
from sbom_generator import generate_sbom

app = FastAPI()

@app.get("/")
def root():
    return {"message": "✅ SBOM API is working"}

# This will activate your `/generate-sbom/` endpoint
app.post("/generate-sbom/")(generate_sbom)

