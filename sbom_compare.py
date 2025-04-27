import json
import os

def load_sbom(file_path):
    """
    Load SBOM JSON file and return the SBOM data.
    """
    if not file_path.endswith(".json"):
        print("❌ Only JSON SBOM files are supported for search.")
        return None

    if not os.path.exists(file_path):
        print(f"❌ SBOM file not found: {file_path}")
        return None

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"❌ Error reading SBOM: {e}")
        return None


"""
sbom_compare.py
---------------
This module provides functionality to compare two SBOM (Software Bill of Materials) JSON objects.
It detects components that have been added, removed, or modified between two SBOMs.
"""

def compare_sboms(sbom1_data, sbom2_data):
    """
    Enhanced SBOM comparison to detect added, removed, and modified components.

    Parameters:
    - sbom1_data: dict - First SBOM JSON data.
    - sbom2_data: dict - Second SBOM JSON data.

    Returns:
    - added: list[dict]   - Components present in sbom2 but not in sbom1.
    - removed: list[dict] - Components present in sbom1 but not in sbom2.
    - modified: list[dict] OR str 
        - List of modified components 
        - OR message string if SBOMs are identical, empty, or if there's an error.
    """
    if not sbom1_data or not sbom2_data:
        return None, None, "❌ One or both SBOMs are missing or invalid."

    try:
        sbom1_components = sbom1_data.get("components", [])
        sbom2_components = sbom2_data.get("components", [])

        if not sbom1_components and not sbom2_components:
            return [], [], "ℹ️ Both SBOMs have no components to compare."

        # Define a unique key for each component based on key attributes
        def get_key(comp):
            return (
                comp.get("name", "Unknown"),
                comp.get("version", "Unknown"),
                comp.get("type", "Unknown"),
                comp.get("purl", ""),
                comp.get("supplier", {}).get("name", "")
            )

        # Create dictionaries keyed by unique component identifiers
        sbom1_dict = {get_key(c): c for c in sbom1_components}
        sbom2_dict = {get_key(c): c for c in sbom2_components}

        # Determine added and removed components
        added_keys = set(sbom2_dict.keys()) - set(sbom1_dict.keys())
        removed_keys = set(sbom1_dict.keys()) - set(sbom2_dict.keys())

        added = sorted([sbom2_dict[k] for k in added_keys], key=lambda x: x.get("name", ""))
        removed = sorted([sbom1_dict[k] for k in removed_keys], key=lambda x: x.get("name", ""))

        # Detect modified components (same key but different details)
        modified = []
        common_keys = set(sbom1_dict.keys()) & set(sbom2_dict.keys())
        for key in common_keys:
            if sbom1_dict[key] != sbom2_dict[key]:
                modified.append({
                    "Component": key,
                    "SBOM 1": sbom1_dict[key],
                    "SBOM 2": sbom2_dict[key]
                })

        # If no differences found
        if not added and not removed and not modified:
            return [], [], "✅ The SBOMs are identical."

        return added, removed, modified

    except Exception as e:
        return None, None, f"❌ Error during comparison: {str(e)}"
