import os
import json
import hashlib
import platform
import subprocess
import pefile

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def secure_filename(filename):
    """
    Sanitize filename to prevent issues such as directory traversal.
    Replaces spaces with underscores and strips out any non-basename paths.
    """
    return os.path.basename(filename).replace(" ", "_")


def calculate_file_hash(file_path):
    """
    Calculates the SHA-256 hash of the specified file in chunks (4096 bytes),
    to handle large files efficiently.
    """
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


def extract_metadata_from_exe(file_path):
    """
    Extract vendor, version, and compiler details from a Windows EXE using pefile.
    Looks for 'CompanyName', 'ProductVersion' or 'FileVersion' in FileInfo StringTable.
    Also includes the linker version as 'compiler' from the OPTIONAL_HEADER.
    Returns (vendor, version, compiler) as strings.
    """
    vendor = "Unknown"
    version = "Unknown"
    compiler = "Unknown"

    try:
        pe = pefile.PE(file_path)

        # Look for StringTable info: 'CompanyName', 'ProductVersion', 'FileVersion'
        if hasattr(pe, "FileInfo") and isinstance(pe.FileInfo, list):
            for fileinfo in pe.FileInfo:
                if hasattr(fileinfo, "StringTable"):
                    for st in fileinfo.StringTable:
                        for key, value in st.entries.items():
                            key_str = key.decode(errors='ignore')
                            value_str = value.decode(errors='ignore').strip()
                            if key_str == "CompanyName":
                                vendor = value_str
                            elif key_str in ["ProductVersion", "FileVersion"]:
                                # You might decide which one to prioritize if both exist
                                version = value_str

        # OPTIONAL_HEADER might give us the major/minor linker version
        if hasattr(pe, "OPTIONAL_HEADER"):
            linker_major = pe.OPTIONAL_HEADER.MajorLinkerVersion
            linker_minor = pe.OPTIONAL_HEADER.MinorLinkerVersion
            compiler = f"Linker {linker_major}.{linker_minor}"

    except Exception as e:
        print(f"⚠️ Error reading PE metadata: {e}")

    return vendor, version, compiler


def generate_sbom(file_path):
    """
    Generates an SBOM for a given file, using Syft (by anchore) with CycloneDX JSON output.
    It:
     1. Checks file existence
     2. Calculates a file hash (SHA-256)
     3. Extracts EXE metadata if applicable (vendor, version, compiler)
     4. Runs `syft <file_path> -o cyclonedx-json`
     5. Loads Syft's output (stdout) as JSON
     6. Appends top-level metadata (vendor, version, compiler, etc.)
     7. Saves final SBOM to <BASE_DIR>/sbom_outputs/<filename>.json
     8. Returns the path to that final SBOM file, or None on error
    """
    try:
        if not os.path.exists(file_path):
            print(f"❌ Error: File {file_path} not found.")
            return None

        file_name = os.path.basename(file_path)

        # 1) Calculate file hash
        file_hash = calculate_file_hash(file_path)

        # 2) Extract EXE metadata if file is an .exe
        vendor, version, compiler = "Unknown", "Unknown", "Unknown"
        if file_path.lower().endswith(".exe"):
            vendor, version, compiler = extract_metadata_from_exe(file_path)

        # 3) Prepare output path
        output_dir = os.path.join(BASE_DIR, "sbom_outputs")
        os.makedirs(output_dir, exist_ok=True)
        output_sbom = os.path.join(output_dir, secure_filename(file_name) + ".json")

        # 4) Run Syft to generate CycloneDX JSON
        #    Make sure Syft is installed and available on the PATH
        command = ["syft", file_path, "-o", "cyclonedx-json"]
        result = subprocess.run(command, capture_output=True, text=True)

        if result.returncode != 0:
            print(f"❌ Syft Error: {result.stderr}")
            return None

        # 5) Parse Syft’s JSON output from stdout
        sbom_json = json.loads(result.stdout)

        # 6) Append top-level metadata
        sbom_json.update({
            "Software Name": file_name,
            "Vendor": vendor,
            "Version": version,
            "File Hash": file_hash,                # SHA-256
            "Format": "CycloneDX",                 # or 'SPDX', if you prefer
            "OS Compatibility": platform.system(), # e.g., 'Windows', 'Linux', 'Darwin'
            "Binary Architecture": platform.machine(),
            "Compiler": compiler
        })

        # 7) Save final SBOM JSON
        with open(output_sbom, "w", encoding="utf-8") as f:
            json.dump(sbom_json, f, indent=2)

        print(f"✅ SBOM generated successfully: {output_sbom}")
        return output_sbom

    except Exception as e:
        print(f"❌ Exception in generate_sbom: {e}")
        return None
