import json
from fuzzywuzzy import fuzz


def load_sbom(file_path):
    """
    Load an SBOM JSON file from the specified path.

    Parameters:
        file_path (str): Path to the SBOM file.

    Returns:
        dict: Parsed SBOM content or None if error.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"❌ Error reading SBOM: {e}")
        return None


from fuzzywuzzy import fuzz

def fuzzy_search_components(sbom_data, apk_details, query, threshold=60):
    results = []

    # 1. Search SBOM Components
    components = sbom_data.get("components", []) if sbom_data else []
    for comp in components:
        for field in ["name", "purl", "group", "description"]:
            value = comp.get(field, "")
            if value and fuzz.partial_ratio(query.lower(), value.lower()) >= threshold:
                results.append({
                    "Type": "SBOM Component",
                    "Match": value,
                    "Field": field
                })
                break

    # 2. Search APK Permissions
    if apk_details:
        for perm in apk_details.get("Permissions", []):
            if fuzz.partial_ratio(query.lower(), perm.lower()) >= threshold:
                results.append({
                    "Type": "Permission",
                    "Match": perm,
                    "Field": "uses-permission"
                })

    # 3. Search APK Libraries
    for lib in apk_details.get("Libraries", []):
        if fuzz.partial_ratio(query.lower(), lib.lower()) >= threshold:
            results.append({
                "Type": "Library",
                "Match": lib,
                "Field": "native/shared lib"
            })

    # 4. Search Smali Packages
    for smali in apk_details.get("Packages", []):
        if fuzz.partial_ratio(query.lower(), smali.lower()) >= threshold:
            results.append({
                "Type": "Smali Package",
                "Match": smali,
                "Field": "smali"
            })

    # 5. Search APK Metadata (e.g., package info)
    meta = apk_details.get("Package Info", "")
    if fuzz.partial_ratio(query.lower(), meta.lower()) >= threshold:
        results.append({
            "Type": "Package Info",
            "Match": meta,
            "Field": "package"
        })

    return results

