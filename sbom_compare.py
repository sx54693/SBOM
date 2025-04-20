import json
import os

def load_sbom(file_path):
    """
    Loads SBOM from a JSON file and extracts its components.

    Parameters:
    - file_path: str - Path to the SBOM file.

    Returns:
    - dict: Parsed SBOM JSON content.
    """
    if not os.path.exists(file_path):
        print(f"❌ Error: SBOM file {file_path} not found.")
        return None
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        print(f"❌ Error: Invalid JSON format in {file_path}")
    except Exception as e:
        print(f"❌ Error loading SBOM: {e}")
    return None

def compare_sboms(sbom1_data, sbom2_data):
    """
    Compare two SBOMs (dictionaries) and identify added/removed components.

    Parameters:
    - sbom1_data: dict - First SBOM as JSON dictionary.
    - sbom2_data: dict - Second SBOM as JSON dictionary.

    Returns:
    - added: list[dict] - Components present in sbom2 but not in sbom1
    - removed: list[dict] - Components present in sbom1 but not in sbom2
    - error: str or None - Error message if any
    """
    if not sbom1_data or not sbom2_data:
        return None, None, "❌ One or both SBOMs are missing or invalid."

    try:
        sbom1_components = sbom1_data.get("components", [])
        sbom2_components = sbom2_data.get("components", [])

        def get_key(comp):
            return (comp.get("name", "Unknown"), comp.get("version", "Unknown"), comp.get("type", "Unknown"))

        sbom1_dict = {get_key(c): c for c in sbom1_components}
        sbom2_dict = {get_key(c): c for c in sbom2_components}

        sbom1_keys = set(sbom1_dict.keys())
        sbom2_keys = set(sbom2_dict.keys())

        added_keys = sbom2_keys - sbom1_keys
        removed_keys = sbom1_keys - sbom2_keys

        added = [sbom2_dict[k] for k in added_keys]
        removed = [sbom1_dict[k] for k in removed_keys]

        return added, removed, None
    except Exception as e:
        return None, None, f"❌ Error during comparison: {str(e)}"

