import os
import json

def compare_sboms(sbom1, sbom2):
    """
    Compare two SBOMs. Each argument (sbom1, sbom2) can be:
      1) A file path (string) to a JSON SBOM
      2) A dict already loaded in memory

    Returns:
      (added, removed, error) where:
        - added is a set of component names present in sbom2 but not in sbom1
        - removed is a set of component names present in sbom1 but not in sbom2
        - error is a string if something went wrong, else None
    """

    def load_sbom(data_or_path):
        """Load SBOM JSON from a file path or return it if it's already a dict."""
        if isinstance(data_or_path, dict):
            # It's already SBOM data in memory
            return data_or_path

        if isinstance(data_or_path, str) and os.path.exists(data_or_path):
            # It's a valid path to a JSON file
            try:
                with open(data_or_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                print(f"❌ Failed to read SBOM file {data_or_path}: {e}")
                return None

        # If we get here, it's invalid input
        return None

    # Load both SBOMs (from disk or memory)
    sbom_data_1 = load_sbom(sbom1)
    sbom_data_2 = load_sbom(sbom2)

    if sbom_data_1 is None or sbom_data_2 is None:
        return None, None, "One or both SBOMs could not be loaded."

    # Grab components lists (default to empty if missing)
    components_1 = sbom_data_1.get("components", [])
    components_2 = sbom_data_2.get("components", [])

    # Convert the list of components to a set of names
    def get_component_names(components_list):
        # This assumes each component is a dict with a 'name' key
        return {comp.get("name") for comp in components_list if comp.get("name")}

    set_1 = get_component_names(components_1)
    set_2 = get_component_names(components_2)

    # Determine which components are added or removed
    added = set_2 - set_1
    removed = set_1 - set_2

    # No error occurred, so return results
    return added, removed, None
