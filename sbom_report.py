import json

def format_sbom_report(sbom_file):
    """Formats and displays SBOM report."""
    with open(sbom_file, "r", encoding="utf-8") as f:
        sbom_data = json.load(f)

    print("=== SBOM Report ===")
    print(f"Software: {sbom_data['metadata'].get('file_name', 'Unknown')}")
    print(f"Version: {sbom_data['metadata'].get('version', 'Unknown')}")
    print(f"Vendor: {sbom_data['metadata'].get('vendor', 'Unknown')}")
    print(f"License: {sbom_data.get('license', 'Unknown')}")
    print(f"Binary Type: {sbom_data['metadata'].get('binary_type', 'Unknown')}")

    print("\n== Dependencies ==")
    for dep in sbom_data.get("components", []):
        print(f"- {dep['name']} ({dep.get('version', 'Unknown')})")

format_sbom_report("sbom_outputs/example.json")
