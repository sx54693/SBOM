import os
import subprocess
import json
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

        print(f"✅ Extracted Metadata: {metadata}")  # Debugging output

    except Exception as e:
        print(f"❌ EXE Metadata Extraction Failed: {e}")

    return metadata

def generate_sbom(file_path):
    """Generates SBOM for a software application by extracting and scanning it."""
    if not os.path.exists(file_path):
        print(f"❌ Error: File {file_path} not found.")
        return None

    metadata = extract_exe_metadata(file_path)  # Extract EXE metadata
    output_sbom = os.path.join("sbom_outputs", os.path.basename(file_path) + ".json")
    os.makedirs("sbom_outputs", exist_ok=True)

    try:
        command = ["syft", f"file:{file_path}", "-o", "cyclonedx-json"]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Debug Output
        print(f"🔍 Syft Command: {' '.join(command)}")
        print(f"📝 Syft Output:\n{result.stdout}")
        print(f"WARNING: Syft Errors:\n{result.stderr}")

        if result.returncode != 0:
            print(f"❌ Syft Command Failed: {result.stderr}")
            return None  # Stop if Syft fails

        # Save SBOM JSON
        with open(output_sbom, "w", encoding="utf-8") as f:
            f.write(result.stdout)

        # Inject extracted metadata into SBOM JSON
        with open(output_sbom, "r+", encoding="utf-8") as f:
            sbom_data = json.load(f)
            sbom_data.setdefault("metadata", {})  # Ensure metadata exists
            
            # Log metadata before inserting it into SBOM
            print(f"🔍 Injecting Metadata into SBOM: {metadata}")

            sbom_data["metadata"]["Software Name"] = metadata["Software Name"]
            sbom_data["metadata"]["Vendor"] = metadata["Vendor"]
            sbom_data["metadata"]["Version"] = metadata["Version"]
            sbom_data["metadata"]["File Description"] = metadata["File Description"]

            f.seek(0)
            json.dump(sbom_data, f, indent=4)

        print(f"✅ SBOM generated successfully: {output_sbom}")
        return output_sbom
    except FileNotFoundError:
        print("❌ Error: Syft is not installed or not in system path.")
    except PermissionError:
        print("❌ Permission Error: Cannot write SBOM file.")
    except Exception as e:
        print(f"❌ Unexpected Error: {e}")

    return None
