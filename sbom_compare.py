import json
import os

def compare_sboms(sbom1_data, sbom2_data):
    """
    Compare two SBOMs in detail, identifying:
      - Added:   Components in SBOM2 not in SBOM1.
      - Removed: Components in SBOM1 not in SBOM2.
      - Changed: Components with the same name in both, but with different metadata
                (e.g., version, supplier, etc.).

    Each argument (sbom1_data, sbom2_data) is expected to be a Python dict
    with a "components" list, each component having fields like "name", "version",
    "supplier", etc. For instance, a typical CycloneDX or Syft output.

    Returns a tuple:
      (added_list, removed_list, changed_list, error)
        - added_list:   list of components newly introduced in sbom2
        - removed_list: list of components that are missing from sbom2
        - changed_list: list of tuples (component_name, details_of_old, details_of_new)
        - error:        string if something goes wrong, else None
    """

    # Sanity check
    if not sbom1_data or not sbom2_data:
        return None, None, None, "One or both SBOMs are empty or invalid."

    # Extract components or default to empty
    components1 = sbom1_data.get("components", [])
    components2 = sbom2_data.get("components", [])

    # Convert the list of components to a dict keyed by "name" for easier lookup.
    # Because multiple fields can define a unique component (purl, name, version),
    # decide how you want to identify a "component". For simplicity, we use the "name"
    # as the key. If you want a more robust key, use something like (name, purl).
    def component_key(comp):
        # This is the identity used for "which" component
        return comp.get("name", "")

    # Create dicts keyed by "name"
    map1 = {}
    for c in components1:
        key = component_key(c)
        if key:  # Only store if there's a name
            map1[key] = c

    map2 = {}
    for c in components2:
        key = component_key(c)
        if key:
            map2[key] = c

    added = []
    removed = []
    changed = []

    # 1) Identify "removed" and "changed"
    for comp_name, comp1 in map1.items():
        if comp_name not in map2:
            # It's in SBOM1 but not in SBOM2 -> removed
            removed.append(comp1)
        else:
            # The same named component is in both SBOMs
            comp2 = map2[comp_name]

            # Compare the fields that matter
            # For example, you might compare version, supplier, or other metadata
            version1 = comp1.get("version", "N/A")
            version2 = comp2.get("version", "N/A")

            supplier1 = ""
            supplier2 = ""
            # Sometimes supplier info is nested. Adjust as needed:
            # CycloneDX might store it as comp["supplier"]["name"]
            # Syft might store it differently. This is an example:
            if "supplier" in comp1 and isinstance(comp1["supplier"], dict):
                supplier1 = comp1["supplier"].get("name", "")
            if "supplier" in comp2 and isinstance(comp2["supplier"], dict):
                supplier2 = comp2["supplier"].get("name", "")

            # Compare relevant fields
            # If they differ, we consider it a "changed" component
            if (version1 != version2) or (supplier1 != supplier2):
                changed.append((
                    comp_name,
                    {
                        "version": version1,
                        "supplier": supplier1,
                    },
                    {
                        "version": version2,
                        "supplier": supplier2,
                    }
                ))

    # 2) Identify "added"
    for comp_name, comp2 in map2.items():
        if comp_name not in map1:
            # It's in SBOM2 but not in SBOM1 -> added
            added.append(comp2)

    return added, removed, changed, None
