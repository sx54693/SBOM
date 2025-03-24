import os
import json
import pefile
import platform
import hashlib
import subprocess


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
    try:
        if not os.path.exists(file_path):
            print(f"❌ File not found: {file_path}")
            return None

        metadata = extract_metadata(file_path)

        # Run Syft to generate real SBOM components
        syft_cmd = ["syft", file_path, "-o", "cyclonedx-json"]
        syft_result = subprocess.run(syft_cmd, capture_output=True, text=True)

        if syft_result.returncode != 0:
            print(f"❌ Syft failed: {syft_result.stderr}")
            return None

        sbom_data = json.loads(syft_result.stdout)

        # Update metadata accurately
        sbom_data["metadata"] = {
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
        }

        # Include additional properties
        sbom_data["additionalProperties"] = {
            "Compiler": metadata["Compiler"],
            "Platform": metadata["Platform"],
            "Digital Signature": metadata["Digital Signature"],
            "SHA256": calculate_sha256(file_path)
        }

        # Save SBOM JSON file
        output_dir = "sbom_outputs"
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, secure_filename(file_path) + "_sbom.json")

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(sbom_data, f, indent=2)

        print(f"✅ SBOM generated successfully: {output_path}")
        return output_path

    except Exception as e:
        print(f"❌ Error generating SBOM: {e}")
        return None
