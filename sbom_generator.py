import os
import json
import pefile
import platform
import hashlib
import tempfile
import subprocess
from fastapi import FastAPI, UploadFile, File

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
        "Generated On": "N/A",
        "Tool Used": "Syft",
        "Tool Version": "1.6",
        "Vendor": "Unknown",
        "Compiler": "Unknown",
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
        except Exception as e:
            metadata["error"] = str(e)

    return metadata


def run_syft(file_path):
    try:
        result = subprocess.run(
            ["syft", f"dir:{file_path}", "-o", "cyclonedx-json"],
            capture_output=True,
            text=True,
            check=True
        )
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        return {"error": e.stderr}


@app.post("/generate-sbom/")
async def generate_sbom(file: UploadFile = File(...)):
    with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
        content = await file.read()
        tmp_file.write(content)
        tmp_file_path = tmp_file.name

    metadata = extract_metadata(tmp_file_path)
    components_sbom = run_syft(tmp_file_path)

    if "error" in components_sbom:
        os.unlink(tmp_file_path)
        return {"error": components_sbom["error"]}

    sbom_json = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {
            "timestamp": metadata["Generated On"],
            "component": {"name": metadata["Software Name"], "type": "application"},
            "tools": [{"name": metadata["Tool Used"], "version": metadata["Tool Version"]}],
            "supplier": {"name": metadata["Vendor"]}
        },
        "components": components_sbom.get("components", []),
        "additionalProperties": {
            "Compiler": metadata["Compiler"],
            "Platform": metadata["Platform"],
            "Digital Signature": metadata["Digital Signature"],
            "SHA256": calculate_sha256(tmp_file_path)
        }
    }

    os.unlink(tmp_file_path)
    return sbom_json
