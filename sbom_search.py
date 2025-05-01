import json
from fuzzywuzzy import fuzz

def load_sbom(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"❌ Error reading SBOM: {e}")
        return None

def fuzzy_search_components(sbom_data, details, query, threshold=60):
    results = []

    print(f"\n🔍 Starting search for: '{query}' (Threshold: {threshold})")

    # 1. SBOM Components
    components = sbom_data.get("components", []) if sbom_data else []
    print(f"Components found: {len(components)}")

    for comp in components:
        for field in ["name", "purl", "group", "description"]:
            value = comp.get(field, "")
            score = fuzz.partial_ratio(query.lower(), value.lower()) if value else 0
            print(f"Checking component {field}: {value} → Score: {score}")
            if value and score >= threshold:
                results.append({
                    "Type": "SBOM Component",
                    "Match": value,
                    "Field": field
                })
                break

    # 2. Permissions
    for perm in details.get("Permissions", []):
        score = fuzz.partial_ratio(query.lower(), perm.lower())
        print(f"Permission: {perm} → Score: {score}")
        if score >= threshold:
            results.append({
                "Type": "Permission",
                "Match": perm,
                "Field": "uses-permission"
            })

    # 3. Libraries
    for lib in details.get("Libraries", []):
        score = fuzz.partial_ratio(query.lower(), lib.lower())
        print(f"Library: {lib} → Score: {score}")
        if score >= threshold:
            results.append({
                "Type": "Library",
                "Match": lib,
                "Field": "native/shared lib"
            })

    # 4. Smali Packages
    for smali in details.get("Packages", []):
        score = fuzz.partial_ratio(query.lower(), smali.lower())
        print(f"Smali: {smali} → Score: {score}")
        if score >= threshold:
            results.append({
                "Type": "Smali Package",
                "Match": smali,
                "Field": "smali"
            })

    # 5. Metadata
    for key in ["Package Info", "Metadata", "Platform", "Compiler", "Tool", "Signature"]:
        value = details.get(key)
        if isinstance(value, str):
            score = fuzz.partial_ratio(query.lower(), value.lower())
            print(f"Metadata {key}: {value} → Score: {score}")
            if score >= threshold:
                results.append({
                    "Type": "Metadata",
                    "Match": value,
                    "Field": key
                })

    print(f"🔎 Total matches found: {len(results)}\n")
    return results
