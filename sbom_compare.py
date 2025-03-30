import os
import json

def compare_sboms(sbom1, sbom2):
    """
    Compare two SBOMs. Each argument (sbom1, sbom2) can be either:
      1) A file path (string) to a JSON SBOM, OR
      2) A dict already loaded in memory (the SBOM contents).

    Returns:
      (added, removed, error)
        - added: set of component names present in sbom2 but not in sbom1
        - removed: set of component names present in sbom1 but not in sbom2
        - error: string describing an error, or None if no error
    """

    def load_sbom(data_or_path):
        """
        Load SBOM JSON from a file path or return it if it's already a dict.
        If invalid or can't be opened, return None.
        """
        # If it's already a dict, assume it's valid SBOM data
        if isinstance(data_or_path, dict):
            return data_or_path

        # If it's a string, check if it points to an existing file
        if isinstance(data_or_path, str) and os.path.exists(data_or_path):
            try:
                with open(data_or_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                print(f"❌ Failed to read SBOM file '{data_or_path}': {e}")
                return None

        # Otherwise, it's not a valid dict or a valid path
        return None

    # Try to load both SBOMs (from dict or file)
    sbom_data_1 = load_sbom(sbom1)
    sbom_data_2 = load_sbom(sbom2)

    if sbom_data_1 is None or sbom_data_2 is None:
        return None, None, "One or both SBOMs could not be loaded."

    # Extract components lists from each SBOM (default to empty list if missing)
    components_1 = sbom_data_1.get("components", [])
    components_2 = sbom_data_2.get("components", [])

    # Convert each list of components to a set of names
    def get_component_names(components_list):
        # Assumes each component is a dict with a 'name' key
        return {comp.get("name") for comp in components_list if comp.get("name")}

    set_1 = get_component_names(components_1)
    set_2 = get_component_names(components_2)

    # Determine which components were added vs. removed
    added = set_2 - set_1
    removed = set_1 - set_2

    # Return the results (no error)
    return added, removed, None
