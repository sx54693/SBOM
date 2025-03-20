import os
import json
import pefile
import hashlib
import platform
import subprocess

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def secure_filename(filename):
    """Sanitize filename to prevent issues."""
    return os.path.basename(filename).replace(" ", "_")

def calculate_file_hash(file_path):
    """Calculates SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        print(f"❌ Error: File {file_path} not found.")
        return None
    except Exception as e:
        print(f"❌ Exception in calculating hash: {e}")
        return None

def get_pe_signature(file_path):
    """Checks if an EXE file has a digital signature."""
    try:
        pe = pefile.PE(file_path)
        if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
            print("✅ Digital Signature Found.")
            return "Signed"
        else:
            print("⚠️ No Digital Signature Found.")
            return "Not Signed"
    except Exception as e:
        print(f"❌ PE Signature Error: {e}")
        return "Not Available"

def extract_metadata_from_exe(file_path):
    """Extracts vendor, version, and compiler details from an EXE file."""
    vendor, version, compiler = "Unknown", "Unknown", "Unknown"

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
                                vendor = value_str
                            elif key_str in ["ProductVersion", "FileVersion"]:
                                version = value_str

        compiler = f"Linker {pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}"
    except Exception as e:
        print(f"⚠️ Error reading PE metadata: {e}")

    return vendor, version, compiler

def enrich_sbom(sbom_json):
    """Adds missing metadata to ensure analytics can be displayed."""
    for component in sbom_json.get("components", []):
        if "supplier" not in component or not isinstance(component["supplier"], dict):
            component["supplier"] = {"name": "Unknown Vendor"}
        if "publisher" not in component or not isinstance(component["publisher"], str):
            component["publisher"] = "Unknown Manufacturer"
        if "type" not in component:
            component["type"] = "Unknown Category"
        if "properties" not in component or not isinstance(component["properties"], list):
            component["properties"] = [{"name": "OS", "value": platform.system()}]
    return sbom_json

def generate_sbom(file_path):
    """Generates an SBOM for the given file, extracting metadata and running Syft for analysis."""
    try:
        if not os.path.exists(file_path):
            print(f"❌ Error: File {file_path} not found.")
            return None

        file_name = os.path.basename(file_path)
        file_hash = calculate_file_hash(file_path)
        digital_signature = get_pe_signature(file_path) if file_path.endswith(".exe") else "Not Available"

        vendor, version, compiler = "Unknown", "Unknown", "Unknown"
        if file_path.endswith(".exe"):
            vendor, version, compiler = extract_metadata_from_exe(file_path)

        output_dir = os.path.join(BASE_DIR, "sbom_outputs")
        os.makedirs(output_dir, exist_ok=True)
        output_sbom = os.path.join(output_dir, secure_filename(file_name) + ".json")

        # Run Syft to generate SBOM
        command = ["syft", file_path, "-o", "cyclonedx-json"]
        result = subprocess.run(command, capture_output=True, text=True)

        if result.returncode != 0:
            print(f"❌ Syft Error: {result.stderr}")
            return None

        sbom_json = json.loads(result.stdout)

        # ✅ Ensure SBOM JSON contains components
        if not sbom_json.get("components"):
            sbom_json["components"] = [{"name": "PlaceholderComponent", "type": "software"}]  # Add a placeholder

        # ✅ Enrich SBOM with missing metadata
        sbom_json = enrich_sbom(sbom_json)

        # ✅ Add top-level metadata
        sbom_json.update({
            "Software Name": file_name,
            "Vendor": vendor if vendor else "Unknown Vendor",
            "Version": version if version else "Unknown Version",
            "Description": f"SBOM for {file_name}",
            "File Hash": file_hash,
            "Format": "CycloneDX",
            "Digital Signature": digital_signature,
            "OS Compatibility": platform.system(),
            "Binary Architecture": platform.machine(),
            "Compiler": compiler
        })

        # ✅ Save the final enriched SBOM JSON
        with open(output_sbom, "w", encoding="utf-8") as f:
            json.dump(sbom_json, f, indent=2)

        print(f"✅ SBOM generated successfully: {output_sbom}")
        return output_sbom

    except Exception as e:
        print(f"❌ Exception in generate_sbom: {e}")
        return None

