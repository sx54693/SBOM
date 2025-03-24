import os
import json
import pefile
import subprocess
import platform
from fastapi import UploadFile, File

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def secure_filename(filename):
    """Sanitize filename to prevent path traversal and formatting issues."""
    return os.path.basename(filename).replace(" ", "_")

def extract_metadata(file_path):
    """Extracts compiler, vendor, platform, and digital signature from EXE"""
    metadata = {
        "Software Name": os.path.basename(file_path),
        "Format": "CycloneDX",
        "Version": "Unknown",
        "Generated On": "N/A",
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
                                key_str = key.decode(errors="ignore").strip()
                                value_str = value.decode(errors="ignore").strip()
                                if key_str == "CompanyName":
                                    metadata["Vendor"] = value_str

            metadata["Digital Signature"] = check_digital_signature(file_path)

        except Exception as e:
            metadata["Compiler"] = "Error Extracting Compiler"
            metadata["Vendor"] = f"Error Extracting Vendor: {str(e)}"
            metadata["Digital Signature"] = "Signature Check Failed"

    return metadata

def check_digital_signature(file_path):
    """Checks if the EXE has a digital signature using signtool.exe (Windows only)"""
    signtool_path = "C:\\Users\\cyria\\signtool.exe"  # Adjust path as needed
    if not os.path.exists(signtool_path):
        return "⚠️ Signature Check Tool Not Found"

    try:
        result = subprocess.run(
            [signtool_path, "verify", "/pa", file_path],
            capture_output=True,
            text=True
        )
        if "Successfully verified" in result.stdout:
            return "✅ Signed"
        elif "No signature" in result.stdout or "is not signed" in result.stdout:
            return "❌ Not Signed"
        return "⚠️ Unknown Signature Status"
    except Exception:
        return "❌ Signature Check Failed"

def generate_sbom(file_path):
    """Generates an SBOM JSON from the given executable"""
    try:
        if not os.path.exists(file_path):
            print(f"❌ Error: File not found: {file_path}")
            return None

        metadata = extract_metadata(file_path)

        sbom_data = {
            "metadata": metadata,
            "components": []  # You can fill this using syft or dynamic analysis later
        }

        output_dir = os.path.join(BASE_DIR, "sbom_outputs")
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, secure_filename(file_path) + ".json")

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(sbom_data, f, indent=2)

        print(f"✅ SBOM generated at: {output_path}")
        return output_path
    except Exception as e:
        print(f"❌ Exception in generate_sbom(): {e}")
        return None

# Optional FastAPI endpoint (if used separately)
def generate_sbom_from_upload(file: UploadFile):
    """Wrapper for FastAPI to handle uploads directly"""
    file_path = os.path.join("uploaded_apps", secure_filename(file.filename))
    os.makedirs("uploaded_apps", exist_ok=True)
    with open(file_path, "wb") as buffer:
        buffer.write(file.file.read())
    return generate_sbom(file_path)
