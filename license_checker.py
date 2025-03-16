import json
import os

# Known Open-Source and Proprietary Licenses
OPEN_SOURCE_LICENSES = {"MIT", "Apache-2.0", "BSD-3-Clause", "GPL-2.0", "GPL-3.0", "LGPL-2.1", "MPL-2.0", "AGPL-3.0"}
PROPRIETARY_LICENSES = {"Proprietary", "Commercial", "EULA"}

def check_license(sbom_file):
    """Scans an SBOM file for software licenses and detects conflicts."""
    if not os.path.exists(sbom_file):
        print(f"❌ Error: SBOM file {sbom_file} not found.")
        return {"licenses": ["Unknown"], "conflicts": []}

    license_data = {"licenses": [], "conflicts": []}

    try:
        with open(sbom_file, "r", encoding="utf-8") as f:
            sbom_data = json.load(f)

        # Extract licenses from SBOM components
        for component in sbom_data.get("components", []):
            if "licenses" in component:
                for license_info in component["licenses"]:
                    if "license" in license_info and "name" in license_info["license"]:
                        detected_license = license_info["license"]["name"]
                        license_data["licenses"].append(detected_license)

        # Deduplicate licenses
        license_data["licenses"] = list(set(license_data["licenses"]))

        # Check for conflicts
        has_open_source = any(lic in OPEN_SOURCE_LICENSES for lic in license_data["licenses"])
        has_proprietary = any(lic in PROPRIETARY_LICENSES for lic in license_data["licenses"])

        if has_open_source and has_proprietary:
            license_data["conflicts"].append("⚠️ Possible conflict: Open-source and proprietary licenses detected.")

        if "GPL-3.0" in license_data["licenses"] and "MIT" in license_data["licenses"]:
            license_data["conflicts"].append("⚠️ Conflict: GPL-3.0 is not fully compatible with MIT in some cases.")

    except json.JSONDecodeError:
        print("❌ Error: Invalid JSON format in SBOM file.")
        return {"licenses": ["Invalid SBOM"], "conflicts": ["⚠️ Corrupt or malformed SBOM file."]}

    except Exception as e:
        print(f"❌ License Scan Error: {e}")
        return {"licenses": ["Error"], "conflicts": [str(e)]}

    return license_data
