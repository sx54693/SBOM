import os
import subprocess
import json
import shutil
import pefile

def extract_exe_metadata(file_path):
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
        print(f"❌ Metadata extraction failed: {e}")
    return metadata

def extract_apk(file_path, extract_dir):
    try:
        os.makedirs(extract_dir, exist_ok=True)
        subprocess.run(["apktool", "d", "-f", file_path, "-o", extract_dir],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return extract_dir
    except Exception as e:
        print(f"❌ APKTool extraction failed: {e}")
        return None

def extract_exe(file_path, extract_dir):
    if not shutil.which("7z"):
        print("❌ 7-Zip not found.")
        return None
    try:
        subprocess.run(["7z", "x", file_path, f"-o{extract_dir}"],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return extract_dir
    except Exception as e:
        print(f"❌ 7-Zip extraction failed: {e}")
        return None

def is_valid_json(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            json.load(f)
        return True
    except:
        return False

def generate_sbom(file_path):
    if not os.path.exists(file_path):
        print("❌ File not found.")
        return None

    file_path = os.path.abspath(file_path)
    file_ext = os.path.splitext(file_path)[1].lower()
    sbom_output_dir = os.path.abspath("sbom_outputs")
    os.makedirs(sbom_output_dir, exist_ok=True)
    output_sbom = os.path.join(sbom_output_dir, os.path.basename(file_path) + ".json")

    scan_target = None
    metadata = {
        "Software Name": os.path.basename(file_path),
        "Version": "Unknown",
        "Vendor": "Unknown",
        "File Description": "Unknown"
    }

    if file_ext == ".exe":
        metadata = extract_exe_metadata(file_path)
        extracted_dir = os.path.join("extracted_apps", os.path.basename(file_path))
        scan_target = extract_exe(file_path, extracted_dir)
        if not scan_target:
            return None
        scan_target = f"dir:{scan_target}"

    elif file_ext == ".apk":
        extracted_dir = os.path.join("decoded_apks", os.path.basename(file_path).replace(".apk", ""))
        scan_target = extract_apk(file_path, extracted_dir)
        if not scan_target:
            return None
        scan_target = f"dir:{scan_target}"

    else:
        scan_target = f"file:{file_path}"

    try:
        command = ["syft", scan_target, "-o", "cyclonedx-json"]
        result = subprocess.run(command, capture_output=True, text=True)

        if result.returncode != 0 or not result.stdout.strip():
            print("❌ Syft failed or returned no output.")
            return None

        with open(output_sbom, "w", encoding="utf-8") as f:
            f.write(result.stdout)

        if is_valid_json(output_sbom):
            with open(output_sbom, "r+", encoding="utf-8") as f:
                sbom_data = json.load(f)
                sbom_data.setdefault("metadata", {})
                sbom_data["metadata"]["Software Name"] = metadata["Software Name"]
                sbom_data["metadata"]["Vendor"] = metadata["Vendor"]
                sbom_data["metadata"]["Version"] = metadata["Version"]
                sbom_data["metadata"]["File Description"] = metadata["File Description"]
                f.seek(0)
                json.dump(sbom_data, f, indent=4)
                f.truncate()
            print(f"✅ SBOM saved: {output_sbom}")
            return output_sbom
        else:
            print("❌ Invalid SBOM JSON.")
            return None
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return None
