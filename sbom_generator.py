import os
import json
import pefile
import platform
import hashlib
import subprocess

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def secure_filename(filename):
    """Safely transform the file name, removing path components and replacing spaces."""
    return os.path.basename(filename).replace(" ", "_")

def calculate_sha256(file_path):
    """Calculate SHA-256 hash of a file in chunks."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def extract_metadata(file_path):
    """Extract metadata for EXE files using pefile."""
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
        "Digital Signature": "Not Available on Cloud"
    }

    if file_path.lower().endswith(".exe"):
        try:
            pe = pefile.PE(file_path)

            # Compiler (linker) version
            if hasattr(pe, "OPTIONAL_HEADER"):
                major = pe.OPTIONAL_HEADER.MajorLinkerVersion
                minor = pe.OPTIONAL_HEADER.MinorLinkerVersion
                metadata["Compiler"] = f"Linker {major}.{minor}"

            # Extract vendor from string table
            if hasattr(pe, "FileInfo"):
                for file_info in pe.FileInfo:
                    if hasattr(file_info, "StringTable"):
                        for entry in file_info.StringTable:
                            for key, value in entry.entries.items():
                                key_str = key.decode(errors="ignore").strip()
                                value_str = value.decode(errors="ignore").strip()
                                if key_str.lower() == "companyname":
                                    metadata["Vendor"] = value_str
        except Exception as e:
            metadata["Vendor"] = f"Error extracting vendor: {e}"

    return metadata

def generate_sbom(file_path):
    """Generates a CycloneDX SBOM using Syft and enriches it with metadata."""
    try:
        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}"}

        metadata = extract_metadata(file_path)

        # Run Syft
        command = ["syft", file_path, "-o", "cyclonedx-json"]
        result = subprocess.run(command, capture_output=True, text=True)

        if result.returncode != 0 or not result.stdout.strip():
            return {"error": f"Syft Error: {result.stderr.strip()}"}

        sbom_json = json.loads(result.stdout)

        # Enrich metadata
        sbom_json["metadata"] = {
            "timestamp": metadata["Generated On"],
            "component": {
                "name": metadata["Software Name"],
                "type": "application"
            },
            "tools": [
                {
                    "name": metadata["Tool Used"],
                    "version": metadata["Tool Version"]
                }
            ],
            "supplier": {
                "name": metadata["Vendor"]
            }
        }

        sbom_json["additionalProperties"] = {
            "Compiler": metadata["Compiler"],
            "Platform": metadata["Platform"],
            "Digital Signature": metadata["Digital Signature"],
            "SHA256": calculate_sha256(file_path)
        }

        # Add notice if no components found
        if not sbom_json.get("components"):
            sbom_json["notice"] = "No components discovered. May be normal for statically-linked EXEs."

        # Save SBOM
        output_dir = os.path.join(BASE_DIR, "sbom_outputs")
        os.makedirs(output_dir, exist_ok=True)
        output_filename = secure_filename(os.path.basename(file_path)) + "_sbom.json"
        output_path = os.path.join(output_dir, output_filename)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(sbom_json, f, indent=2)

        sbom_json["output_path"] = output_path
        return sbom_json

    except Exception as e:
        return {"error": f"Error generating SBOM: {e}"}


