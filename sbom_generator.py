import os
import subprocess

def extract_exe(file_path):
    """Extracts EXE contents using 7-Zip."""
    extract_dir = os.path.join("extracted_apps", os.path.basename(file_path).replace(".exe", ""))
    os.makedirs(extract_dir, exist_ok=True)

    try:
        command = ["7z", "x", file_path, f"-o{extract_dir}", "-y"]
        result = subprocess.run(command, capture_output=True, text=True)

        if result.returncode != 0:
            print(f"❌ 7-Zip Extraction Error: {result.stderr}")
            return None

        print(f"✅ Extracted EXE to: {extract_dir}")
        return extract_dir
    except Exception as e:
        print(f"❌ Extraction Failed: {e}")
        return None

def generate_sbom(file_path):
    """Generates SBOM for a software application by extracting and scanning it."""
    if not os.path.exists(file_path):
        print(f"❌ Error: File {file_path} not found.")
        return None

    if file_path.endswith(".exe"):
        file_path = extract_exe(file_path)
        if not file_path:
            return None  # Extraction failed, stop further processing

    output_sbom = os.path.join("sbom_outputs", os.path.basename(file_path) + ".json")
    os.makedirs("sbom_outputs", exist_ok=True)

    try:
        command = ["syft", f"dir:{file_path}", "-o", "cyclonedx-json"]
        with open(output_sbom, "w", encoding="utf-8") as f:
            result = subprocess.run(command, stdout=f, stderr=subprocess.PIPE, text=True, check=True)

        print(f"✅ SBOM generated successfully: {output_sbom}")
        return output_sbom
    except subprocess.CalledProcessError as e:
        print(f"❌ Syft Error: {e.stderr}")
        return None
    except Exception as e:
        print(f"❌ Unexpected Error: {e}")
        return None
