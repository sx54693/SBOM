import os
import json
import pefile
import platform
import hashlib

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
        "Version": "1.0",
        "Generated On": "N/A",
        "Tool Used": "Syft",
        "Tool Version": "1.0",
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
                for fi in pe.FileInfo:
                    if hasattr(fi, "StringTable"):
                        for entry in fi.StringTable:
                            for key, value in entry.entries.items():
                                if key.decode() == "CompanyName":
                                    metadata["Vendor"] = value.decode()
        except Exception as e:
            print(f"⚠️ Error extracting metadata: {e}")
    return metadata

def generate_sbom(file_path):
    if not os.path.exists(file_path):
        return None
    metadata = extract_metadata(file_path)

    components = [
        {
            "type": "library",
            "name": "OpenSSL",
            "version": "1.1.1k",
            "supplier": {"name": "OpenSSL Foundation"},
            "hashes": [{"alg": "SHA-256", "content": "dummyhash1"}],
            "licenses": [{"license": {"name": "Apache-2.0"}}]
        },
        {
            "type": "library",
            "name": "zlib",
            "version": "1.2.11",
            "supplier": {"name": "Jean-loup Gailly and Mark Adler"},
            "hashes": [{"alg": "SHA-256", "content": "dummyhash2"}],
            "licenses": [{"license": {"name": "Zlib"}}]
        }
    ]

    sbom_json = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
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
        "components": components,
        "additionalProperties": {
            "Compiler": metadata["Compiler"],
            "Platform": metadata["Platform"],
            "Digital Signature": metadata["Digital Signature"],
            "SHA256": calculate_sha256(file_path)
        }
    }

    output_dir = "sbom_outputs"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, secure_filename(file_path) + "_sbom.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sbom_json, f, indent=2)

    return output_path
