import json
import csv
import os

def parse_sbom(sbom_path):
    """Parses SBOM from JSON, SPDX, or CSV format."""
    if not os.path.exists(sbom_path):
        print(f"❌ Error: SBOM file {sbom_path} not found.")
        return None
    
    try:
        if sbom_path.endswith(".json"):
            with open(sbom_path, "r", encoding="utf-8") as f:
                sbom_data = json.load(f)
            return sbom_data if "components" in sbom_data else None
        
        elif sbom_path.endswith(".csv"):
            parsed_data = []
            with open(sbom_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    parsed_data.append(row)
            return parsed_data if parsed_data else None
        
        elif sbom_path.endswith(".spdx"):
            with open(sbom_path, "r", encoding="utf-8") as f:
                spdx_data = f.readlines()
            return {"spdx": spdx_data} if spdx_data else None
        
        else:
            print("❌ Unsupported SBOM format. Use JSON, SPDX, or CSV.")
            return None
    
    except json.JSONDecodeError:
        print(f"❌ Error: Invalid JSON format in {sbom_path}")
    except Exception as e:
        print(f"❌ Error parsing SBOM: {e}")
    
    return None

