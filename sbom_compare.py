import json
import os

def load_sbom(file_path):
    """Loads SBOM JSON file and extracts components."""
    if not os.path.exists(file_path):
        print(f"❌ Error: SBOM file {file_path} not found.")
        return None
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            sbom_data = json.load(f)
        return sbom_data.get("components", [])  # Extract components
    except json.JSONDecodeError:
        print(f"❌ Error: Invalid JSON format in {file_path}")
    except Exception as e:
        print(f"❌ Error loading SBOM: {e}")
    return None

def compare_sboms(sbom1_path, sbom2_path):
    """Compare two SBOMs and identify added/removed components."""
    if not os.path.exists(sbom1_path) or not os.path.exists(sbom2_path):
        return None, None, "❌ One or both SBOMs are missing. Please generate SBOMs first."

    sbom1_components = load_sbom(sbom1_path)
    sbom2_components = load_sbom(sbom2_path)

    if sbom1_components is None or sbom2_components is None:
        return None, None, "❌ One or both SBOMs are invalid. Please ensure valid SBOM files are provided."

    # Extract component names for comparison
    sbom1_names = {comp.get("name", "Unknown") for comp in sbom1_components}
    sbom2_names = {comp.get("name", "Unknown") for comp in sbom2_components}

    added = sbom2_names - sbom1_names
    removed = sbom1_names - sbom2_names

    return added, removed, None


