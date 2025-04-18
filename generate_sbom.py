import os
import json
import subprocess
import shutil
import pefile

def extract_exe_metadata(file_path):
    """Extracts metadata from an EXE file using pefile."""
    metadata = {
        "Software Name": os.path.basename(file_path),
        "Version": "Unknown",
        "Vendor": "Unknown",
        "File Description": "Unknown"
    }

    try:
        pe = pefile.PE(file_path)
        if hasattr(pe, "FileInfo"):
            for file_info in pe.FileInfo:
                if isinstance(file_info, list):
                    for entry in file_info:
                        if hasattr(entry, "StringTable"):
                            for st in entry.StringTable:
                                for key, value in st.entries.items():
                                    key = key.decode("utf-8", "ignore")
                                    value = value.decode("utf-8", "ignore")
                                    if key.lower() == "companyname":
                                        metadata["Vendor"] = value
                                    elif key.lower() == "productname":
                                        metadata["Software Name"] = value
                                    elif key.lower() == "productversion":
                                        metadata["Version"] = value
                                    elif key.lower() in ["comments", "filedescription"]:
                                        metadata["File Description"] = value
    except Exception as e:
        print(f"❌ EXE Metadata Extraction Failed: {e}")

    return metadata

def extract_exe(file_path, extract_dir):
    """Extracts EXE file using 7-Zip before SBOM analysis."""
    if not shutil.which("7z"):
        print("❌ Error: 7-Zip is not installed or not in PATH.")
        return None
    try:
        print(f"📂 Extracting {file_path} to {extract_dir}...")
        subprocess.run(["7z", "x", file_path, f"-o{extract_dir}"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return extract_dir if os.path.exists(extract_dir) else None
    except Exception as e:
        print(f"❌ EXE Extraction Failed: {e}")
        return None

def is_valid_sbom(sbom_path):
    """Check if SBOM JSON contains valid components."""
    if not os.path.exists(sbom_path):
        return False
    try:
        with open(sbom_path, "r", encoding="utf-8") as f:
            sbom_data = json.load(f)
        return "components" in sbom_data and bool(sbom_data["components"])
    except (json.JSONDecodeError, UnicodeDecodeError):
        return False

def generate_sbom(file_path):
    """Generate SBOM for a software application or app."""
    file_path = os.path.abspath(file_path)
    sbom_output_dir = os.path.abspath("sbom_outputs")
    os.makedirs(sbom_output_dir, exist_ok=True)

    sbom_output = os.path.join(sbom_output_dir, f"{os.path.basename(file_path)}.json")
    extracted_dir = os.path.join("extracted_apps", os.path.basename(file_path))

    try:
        if file_path.endswith(".exe"):
            extracted_path = extract_exe(file_path, extracted_dir)
            metadata = extract_exe_metadata(file_path)
        else:
            extracted_path = file_path
            metadata = {
                "Software Name": os.path.basename(file_path),
                "Version": "Unknown",
                "Vendor": "Unknown",
                "File Description": "Unknown"
            }

        if not extracted_path:
            print("❌ Extraction failed or file not found.")
            return None

        print(f"🔍 Generating SBOM for: {extracted_path}")
        result = subprocess.run(
            ["syft", f"dir:{extracted_path}", "-o", "cyclonedx-json"],
            capture_output=True, text=True
        )

        if result.returncode != 0:
            print(f"❌ Syft Failed: {result.stderr}")
            return None

        with open(sbom_output, "w", encoding="utf-8") as f:
            f.write(result.stdout)

        with open(sbom_output, "r+", encoding="utf-8") as f:
            sbom_data = json.load(f)
            sbom_data.setdefault("metadata", {})
            sbom_data["metadata"]["Software Name"] = metadata["Software Name"]
            sbom_data["metadata"]["Vendor"] = metadata["Vendor"]
            sbom_data["metadata"]["Version"] = metadata["Version"]
            sbom_data["metadata"]["File Description"] = metadata["File Description"]
            f.seek(0)
            json.dump(sbom_data, f, indent=4)
            f.truncate()

        if is_valid_sbom(sbom_output):
            print(f"✅ SBOM successfully generated: {sbom_output}")
            return sbom_output
        else:
            print("⚠️ SBOM generated but has no components.")
            return sbom_output

    except Exception as e:
        print(f"❌ SBOM Generation Failed: {e}")
        return None
