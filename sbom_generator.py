import os
import json
import platform
import hashlib
import subprocess
import pefile
from fastapi import FastAPI, UploadFile, File

# ✅ Create FastAPI App Instance
app = FastAPI()

# ✅ Base Directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def secure_filename(filename: str) -> str:
    """Sanitize filename to prevent issues."""
    return os.path.basename(filename).replace(" ", "_")

def calculate_file_hash(file_path: str) -> str:
    """Calculates SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"❌ Error: {e}")
        return "Unknown"

def extract_metadata_from_exe(file_path: str) -> dict:
    """Extracts metadata from an EXE file."""
    metadata = {
        "Vendor": "Unknown",
        "Version": "Unknown",
        "Compiler": "Unknown"
    }
    try:
        pe = pefile.PE(file_path)
        if hasattr(pe, 'FileInfo'):
            for fileinfo in pe.FileInfo:
                if hasattr(fileinfo, 'StringTable'):
                    for st in fileinfo.StringTable:
                        for key, value in st.entries.items():
                            key_str = key.decode(errors='ignore')
                            value_str = value.decode(errors='ignore').strip()
                            if key_str == "CompanyName":
                                metadata["Vendor"] = value_str
                            elif key_str in ["ProductVersion", "FileVersion"]:
                                metadata["Version"] = value_str
        return metadata
    except Exception as e:
        print(f"⚠️ Error reading PE metadata: {e}")
        return metadata

@app.get("/")
def home():
    """Root endpoint to check if API is running"""
    return {"message": "SBOM Generator API is running!"}

@app.post("/generate-sbom/")
async def generate_sbom(file: UploadFile = File(...)):
    """Generates an SBOM for an uploaded file."""
    file_path = os.path.join(BASE_DIR, "uploaded_files", secure_filename(file.filename))
    os.makedirs(os.path.dirname(file_path), exist_ok=True)

    with open(file_path, "wb") as buffer:
        buffer.write(file.file.read())

    file_hash = calculate_file_hash(file_path)
    metadata = extract_metadata_from_exe(file_path) if file.filename.endswith(".exe") else {}

    sbom_data = {
        "Software Name": file.filename,
        "File Hash": file_hash,
        "Format": "CycloneDX",
        "OS Compatibility": platform.system(),
        "Binary Architecture": platform.machine(),
        **metadata,
        "Components": ["Component1", "Component2"]  # Dummy data, replace with real SBOM components
    }

    sbom_output_path = os.path.join(BASE_DIR, "sbom_outputs", secure_filename(file.filename) + ".json")
    os.makedirs(os.path.dirname(sbom_output_path), exist_ok=True)
    
    with open(sbom_output_path, "w", encoding="utf-8") as f:
        json.dump(sbom_data, f, indent=4)

    return {"filename": file.filename, "sbom_file": sbom_output_path, "sbom_data": sbom_data}
