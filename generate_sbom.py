import json
import os
import subprocess
import shutil

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

def is_valid_sbom(file_path):
    """Check if SBOM JSON contains valid components."""
    if not os.path.exists(file_path):
        return False
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            sbom_data = json.load(f)
        return "components" in sbom_data and bool(sbom_data["components"])  # Must contain components
    except (json.JSONDecodeError, UnicodeDecodeError):
        return False

def generate_sbom(file_path):
    """Generate SBOM for a file and ensure output is valid."""
    file_path = os.path.abspath(file_path)
    sbom_output_dir = os.path.abspath("sbom_outputs")
    os.makedirs(sbom_output_dir, exist_ok=True)
    
    # SBOM output file
    sbom_output = os.path.join(sbom_output_dir, f"{os.path.basename(file_path)}.json")
    extracted_dir = os.path.join("extracted_apps", os.path.basename(file_path))

    try:
        # Extract EXE before scanning
        extracted_path = extract_exe(file_path, extracted_dir) if file_path.endswith(".exe") else file_path
        if not extracted_path:
            print("❌ Extraction failed, skipping SBOM generation.")
            return None

        print(f"🔍 Generating SBOM for: {extracted_path}")

        # Run Syft on extracted directory
        result = subprocess.run(
            ["syft", f"dir:{extracted_path}", "-o", "cyclonedx-json"],
            capture_output=True, text=True
        )

        # Debugging: Print Syft output
        print("📜 Syft Output:")
        print(result.stdout)

        if result.returncode != 0:
            print(f"❌ Syft Failed: {result.stderr}")
            return None

        # Ensure SBOM is created and has components
        if is_valid_sbom(sbom_output):
            print(f"✅ SBOM Generated Successfully: {sbom_output}")
            return sbom_output
        else:
            print(f"⚠️ Warning: SBOM {sbom_output} has no components.")
            return None

    except Exception as e:
        print(f"❌ SBOM Generation Failed: {e}")
        return None

