import os
import json
import pefile
import platform
import hashlib
from fastapi import FastAPI, UploadFile, File
from fastapi.responses import JSONResponse

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
                                elif key_decoded == "ProductVersion":
                                    metadata["Version"] = value_decoded

        except Exception as e:
            print(f"Metadata extraction failed: {e}")

    return metadata

@app.post("/generate-sbom/")
async def generate_sbom(file: UploadFile = File(...)):
    file_location = f"uploaded_apps/{secure_filename(file.filename)}"
    os.makedirs("uploaded_apps", exist_ok=True)

    try:
        with open(file_location, "wb") as buffer:
            buffer.write(await file.read())

        metadata = extract_metadata(file_location)
        
        sbom_json = {
            "bomFormat": metadata["Format"],
            "specVersion": "1.6",
            "metadata": {
                "timestamp": metadata["Generated On"],
                "component": {
                    "name": metadata["Software Name"],
                    "version": metadata["Version"],
                    "type": "application"
                },
                "tools": [{"name": metadata["Tool Used"], "version": metadata["Tool Version"]}],
                "supplier": {"name": metadata["Vendor"]}
            },
            "components": [{
                "type": "application",
                "name": metadata["Software Name"],
                "version": metadata["Version"],
                "supplier": {"name": metadata["Vendor"]},
                "hashes": [{"alg": "SHA-256", "content": calculate_sha256(file_location)}],
                "licenses": [{"license": {"name": "Proprietary"}}]
            }],
            "additionalProperties": {
                "Compiler": metadata["Compiler"],
                "Platform": metadata["Platform"],
                "Digital Signature": metadata["Digital Signature"]
            }
        }

        return JSONResponse(status_code=200, content=sbom_json)

    except Exception as e:
        error_msg = {"error": f"Internal Server Error: {str(e)}"}
        return JSONResponse(status_code=500, content=error_msg)
