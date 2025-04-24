# sbom_parser.py

import json

def parse_sbom(file_path):
    """
    Parses an SBOM file (currently supports JSON).
    
    :param file_path: Path to the SBOM file.
    :return: Parsed SBOM data as a dictionary, or None if error.
    """
    if file_path.endswith(".json"):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                sbom_data = json.load(f)
            return sbom_data
        except json.JSONDecodeError:
            print(f"❌ Error: Invalid JSON format in {file_path}")
        except Exception as e:
            print(f"❌ Error reading SBOM file: {e}")
    else:
        print(f"⚠️ Unsupported SBOM format for file: {file_path}")
    
    return None
