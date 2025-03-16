import json
from fuzzywuzzy import process

def search_sbom(sbom_file, search_query):
    """Search for a component by name, category, OS, or type, including partial and fuzzy search."""
    try:
        with open(sbom_file, "r", encoding="utf-8") as f:
            sbom_data = json.load(f)

        if "components" not in sbom_data or not sbom_data["components"]:
            print("❌ No components found in SBOM file.")
            return []

        # ✅ Debugging: Print all available components before searching
        print("✅ Available SBOM Components:")
        for component in sbom_data["components"]:
            print(component)

        # ✅ Search using both exact and fuzzy matching
        results = []
        for component in sbom_data["components"]:
            if any(search_query.lower() in str(component.get(field, "")).lower()
                   for field in ["name", "category", "type", "operating_system"]):
                results.append(component)

        # ✅ Fuzzy Matching (if no exact match found)
        if not results:
            component_names = [component.get("name", "") for component in sbom_data["components"]]
            best_matches = process.extract(search_query, component_names, limit=5)
            matched_components = [comp for comp in sbom_data["components"] if comp["name"] in dict(best_matches).keys()]
            results.extend(matched_components)

        # ✅ Debugging: Print search results
        print("🔍 Search Results:", results)
        return results

    except Exception as e:
        print(f"❌ Error in SBOM search: {e}")
        return []

