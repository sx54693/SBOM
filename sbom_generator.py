import os
import json
import subprocess
import platform
import pefile
import hashlib

def secure_filename(filename):
    return os.path.basename(filename).replace(" ", "_")

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

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
            print(f"Metadata extraction failed: {e}")

    return metadata

def generate_sbom(file_path):
    output_dir = "sbom_outputs"
    os.makedirs(output_dir, exist_ok=True)

    try:
        sbom_filename = secure_filename(file_path) + "_sbom.json"
        output_sbom = os.path.join(output_dir, sbom_filename)

        # ✅ Run Syft to dynamically analyze the file/directory
        syft_command = ["syft", file_path, "-o", "cyclonedx-json", "-q"]
        result = subprocess.run(syft_command, capture_output=True, text=True)

        if result.returncode != 0:
            print(f"❌ Syft analysis failed: {result.stderr}")
            return None

        # Parse the output from Syft (JSON)
        sbom_data = json.loads(result.stdout)

        # Enrich SBOM with your metadata
        metadata = extract_metadata(file_path)
        sbom_data["metadata"]["component"] = {
            "name": metadata["Software Name"],
            "type": "application",
            "version": metadata["Version"],
            "supplier": {"name": metadata["Vendor"]},
        }

        sbom_data["additionalProperties"] = {
            "Compiler": metadata["Compiler"],
            "Platform": metadata["Platform"],
            "Digital Signature": metadata["Digital Signature"],
            "SHA256": calculate_sha256(file_path)
        }

        # Save dynamically generated SBOM
        with open(output_sbom, "w", encoding="utf-8") as f:
            json.dump(sbom_data, f, indent=2)

        return output_sbom

    except Exception as e:
        print(f"❌ Error generating SBOM: {e}")
        return None

