import os
import json
import pefile
import platform
import hashlib
import subprocess

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def secure_filename(filename):
    """
    Safely transform the file name, removing any path components and
    replacing spaces with underscores.
    """
    return os.path.basename(filename).replace(" ", "_")

def calculate_sha256(file_path):
    """
    Calculate SHA-256 hash of a file in chunks to handle large files efficiently.
    """
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def extract_metadata(file_path):
    """
    Extract metadata for an EXE file (vendor, compiler, etc.) if available.
    Otherwise, return defaults. This function uses pefile for Windows PE analysis.
    """
    metadata = {
        "Software Name": os.path.basename(file_path),
        "Format": "CycloneDX",
        "Version": "Unknown",
        "Generated On": "N/A",
        "Tool Used": "Syft",
        "Tool Version": "1.0",
        "Vendor": "Unknown",
        "Compiler": "Unknown",
        "Platform": platform.architecture()[0],
        # Adjust the signature field if you have a signature-checking mechanism available.
        "Digital Signature": "Not Available on Cloud"
    }

    if file_path.lower().endswith(".exe"):
        try:
            pe = pefile.PE(file_path)

            # Extract compiler (linker) version
            if hasattr(pe, "OPTIONAL_HEADER"):
                major = pe.OPTIONAL_HEADER.MajorLinkerVersion
                minor = pe.OPTIONAL_HEADER.MinorLinkerVersion
                metadata["Compiler"] = f"Linker {major}.{minor}"

            # Extract vendor (company name) if present
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
            metadata["Vendor"] = f"Error extracting vendor: {e}"

    return metadata

def generate_sbom(file_path):
    """
    Generates a CycloneDX SBOM using Syft for the specified file,
    then enriches it with extra metadata (e.g., vendor, compiler, checksums).
    The final JSON is saved to sbom_outputs/<filename>_sbom.json and also returned.
    """
    try:
        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}"}

        # 1) Extract EXE metadata (if applicable)
        metadata = extract_metadata(file_path)

        # 2) Run Syft to produce CycloneDX JSON
        command = ["syft", file_path, "-o", "cyclonedx-json"]
        result = subprocess.run(command, capture_output=True, text=True)

        if result.returncode != 0:
            return {"error": f"Syft Error: {result.stderr.strip()}"}

        sbom_json = json.loads(result.stdout)

        # 3) Enrich with custom metadata fields
        sbom_json.update({
            "metadata": {
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
            },
            "additionalProperties": {
                "Compiler": metadata["Compiler"],
                "Platform": metadata["Platform"],
                "Digital Signature": metadata["Digital Signature"],
                "SHA256": calculate_sha256(file_path)
            }
        })

        # 4) Optionally check if components is empty
        components = sbom_json.get("components", [])
        if not components:
            sbom_json["notice"] = (
                "No components discovered. This may be normal for a small or statically-linked EXE."
            )

        # 5) Save final SBOM to disk
        output_dir = os.path.join(BASE_DIR, "sbom_outputs")
        os.makedirs(output_dir, exist_ok=True)
        output_filename = secure_filename(file_path) + "_sbom.json"
        output_path = os.path.join(output_dir, output_filename)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(sbom_json, f, indent=2)

        # 6) Return the SBOM plus info about where it was saved
        sbom_json["output_path"] = output_path
        return sbom_json

    except Exception as e:
        return {"error": f"Error generating SBOM: {e}"}

