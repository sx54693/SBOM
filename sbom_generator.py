import os
import json
import hashlib
import platform
import subprocess
import pefile
from platform_utils import detect_binary_type
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ✅ Utility Functions (merged from utils.py)
def secure_filename(filename):
    return os.path.basename(filename).replace(" ", "_")

def calculate_file_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def extract_metadata_from_exe(file_path):
    vendor = version = compiler = "Unknown"
    try:
        pe = pefile.PE(file_path)
        for fileinfo in getattr(pe, "FileInfo", []):
            for st in getattr(fileinfo, "StringTable", []):
                for key, value in st.entries.items():
                    k, v = key.decode(errors='ignore'), value.decode(errors='ignore').strip()
                    if k == "CompanyName": vendor = v
                    elif k in ["ProductVersion", "FileVersion"]: version = v
        if hasattr(pe, "OPTIONAL_HEADER"):
            compiler = f"Linker {pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}"
    except Exception as e:
        print(f"⚠️ Error reading PE metadata: {e}")
    return vendor, version, compiler

def extract_apk_details(file_path):
    try:
        decoded_dir = os.path.join(BASE_DIR, "decoded_apk", os.path.splitext(os.path.basename(file_path))[0])
        os.makedirs(decoded_dir, exist_ok=True)

        # Run apktool with UTF-8 and error fallback
        subprocess.run(
            ["apktool", "d", "-f", file_path, "-o", decoded_dir],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            encoding="utf-8", errors="replace"
        )

        # 📄 Read permissions from manifest
        manifest_path = os.path.join(decoded_dir, "AndroidManifest.xml")
        permissions = []
        if os.path.exists(manifest_path):
            with open(manifest_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if "uses-permission" in line:
                        permissions.append(line.strip())

        # 📦 Extract package info & libraries using aapt
        aapt_output = subprocess.run(
            ["aapt", "dump", "badging", file_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            encoding="utf-8", errors="replace"
        )
        package_info = "Unknown"
        libraries = set()
        known_libs = [
            "androidx", "com.google", "com.android", "org.apache", "kotlin",
            "com.facebook", "com.squareup", "dagger", "javax", "okhttp3"
        ]

        if aapt_output.returncode == 0:
            for line in aapt_output.stdout.splitlines():
                if line.startswith("package:"):
                    package_info = line
                for lib in known_libs:
                    if lib in line:
                        libraries.add(lib)

        return {
            "Package Info": package_info,
            "Permissions": permissions,
            "Libraries": sorted(list(libraries))
        }

    except Exception as e:
        print(f"⚠️ Error extracting APK details: {e}")
        return {
            "Package Info": "Error",
            "Permissions": [],
            "Libraries": []
        }

def generate_sbom(file_path):
    try:
        # Validate file path
        if not file_path or not isinstance(file_path, (str, bytes, os.PathLike)):
            print("❌ Invalid file path provided to generate_sbom.")
            return None, None, None, None, None, None

        if not os.path.exists(file_path):
            print(f"❌ File does not exist: {file_path}")
            return None, None, None, None, None, None

        file_name = os.path.basename(file_path)
        file_hash = calculate_file_hash(file_path)
        vendor, version, compiler = "Unknown", "Unknown", "Unknown"
        
        if file_path.endswith(".exe"):
            vendor, version, compiler = extract_metadata_from_exe(file_path)

        # Prepare output directory
        output_dir = os.path.join(BASE_DIR, "sbom_outputs")
        os.makedirs(output_dir, exist_ok=True)
        output_sbom = os.path.join(output_dir, secure_filename(file_name) + ".json")

        # Run Syft to generate SBOM
        command = ["syft", file_path, "-o", "cyclonedx-json"]
        result = subprocess.run(command, capture_output=True, text=True)

        if result.returncode != 0:
            print(f"❌ Syft error: {result.stderr}")
            return None, None, result.stderr, [], [], {}

        sbom_json = json.loads(result.stdout)

        # Add custom metadata
        sbom_json.update({
            "Software Name": file_name,
            "Vendor": vendor,
            "Version": version,
            "File Hash": file_hash,
            "Format": "CycloneDX",
            "OS Compatibility": platform.system(),
            "Binary Architecture": platform.machine(),
            "Compiler": compiler,
            "Binary Type": detect_binary_type(file_path)
        })

        # Save SBOM to file
        with open(output_sbom, "w", encoding="utf-8") as f:
            json.dump(sbom_json, f, indent=2)

        # APK-specific extraction
        apk_info = extract_apk_details(file_path) if file_path.endswith(".apk") else {}

        return sbom_json, sbom_json, result.stderr, [], [], apk_info

    except json.JSONDecodeError:
        print("❌ Failed to decode SBOM JSON output from Syft.")
        return None, None, "Invalid SBOM JSON format", [], [], {}

    except Exception as e:
        print(f"❌ Unexpected error in generate_sbom: {e}")
        return None, None, None, None, None, None
