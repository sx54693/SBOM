import os
import json
import subprocess
import platform
import hashlib
import pefile
from datetime import datetime

def secure_filename(filename):
    """Sanitize filename to prevent issues."""
    return os.path.basename(filename).replace(" ", "_")

def calculate_sha256(file_path):
    """Calculate SHA-256 hash of the file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def extract_metadata(file_path):
    """Extract metadata from a PE (EXE) file."""
    metadata = {
        "Software Name": os.path.basename(file_path),
        "Format": "CycloneDX",
        "Version": "Unknown",
        "Generated On": datetime.utcnow().isoformat() + "Z",
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

            # Compiler version
            if hasattr(pe, "OPTIONAL_HEADER"):
                metadata["Compiler"] = f"Linker {pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}"

            # Vendor
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
            print(f"⚠️ Metadata extraction failed: {e}")

    return metadata

def generate_sbom(file_path):
    """Generates an SBOM JSON using Syft with real components."""
    if not os.path.exists(file_path):
        print(f"❌ File not found: {file_path}")
        return None

    # Generate SBOM with Syft
    syft_command = ["syft", file_path, "-o", "cyclonedx-json"]
    result = subprocess.run(syft_command, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"❌ Syft failed: {result.stderr}")
        return None

    syft_sbom = json.loads(result.stdout)

    # Extract Metadata
    metadata = extract_metadata(file_path)

    # Construct final SBOM with additional metadata
    sbom_json = {
        "bomFormat": syft_sbom.get("bomFormat", "CycloneDX"),
        "specVersion": syft_sbom.get("specVersion", "1.6"),
        "metadata": {
            "timestamp": metadata["Generated On"],
            "component": {
                "name": metadata["Software Name"],
                "type": "application"
            },
            "tools": [{
                "name": metadata["Tool Used"],
                "version": metadata["Tool Version"]
            }],
            "supplier": {
                "name": metadata["Vendor"]
            }
        },
        "components": syft_sbom.get("components", []),
        "additionalProperties": {
            "Compiler": metadata["Compiler"],
            "Platform": metadata["Platform"],
            "Digital Signature": metadata["Digital Signature"],
            "SHA256": calculate_sha256(file_path)
        }
    }

    # Save SBOM file
    output_dir = "sbom_outputs"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, secure_filename(file_path) + "_sbom.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sbom_json, f, indent=2)

    return output_path
