import streamlit as st
import os
import json
import subprocess
import pandas as pd

# Set Streamlit page title
st.set_page_config(page_title="SBOM Generator & Scanner", layout="wide")

st.title("📜 SBOM Generator & Vulnerability Scanner")

# Ensure the 'SBOM' folder exists
sbom_folder = "SBOM"
os.makedirs(sbom_folder, exist_ok=True)

# 📂 Step 1: Require File Upload First
st.sidebar.subheader("📂 Upload Your Project File")
uploaded_file = st.sidebar.file_uploader(
    "Choose a file (e.g., package.json, requirements.txt, pom.xml)",
    type=["json", "txt"]
)

if not uploaded_file:
    st.warning("⚠️ Please upload a file first to proceed.")
    st.stop()  # Stops further execution until a file is uploaded

# Save uploaded file
file_path = os.path.join(sbom_folder, uploaded_file.name)

with open(file_path, "wb") as f:
    f.write(uploaded_file.read())

st.success(f"✅ Uploaded {uploaded_file.name} successfully!")

# Sidebar Navigation after file selection
st.sidebar.title("🛠️ SBOM Options")
page = st.sidebar.radio("Select a Feature", ["Generate SBOM", "Scan Vulnerabilities", "Compare SBOMs"])

sbom_file = os.path.join(sbom_folder, "sbom_output")

# 📌 Generate SBOM
if page == "Generate SBOM":
    st.subheader("🔍 Generate SBOM for Your Project")

    format_option = st.selectbox("📄 Select SBOM Format", ["CycloneDX JSON", "SPDX JSON", "CSV"])

    if st.button("🔍 Generate SBOM"):
        format_cmd = {
            "CycloneDX JSON": "cyclonedx-json",
            "SPDX JSON": "spdx-json",
            "CSV": "table"
        }
        output_file = f"{sbom_file}.{format_option.split()[0].lower()}"

        cmd = ["syft", f"dir:{sbom_folder}", "-o", format_cmd[format_option]]
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.stdout.strip():
            with open(output_file, "w") as f:
                f.write(result.stdout)

            st.success(f"✅ SBOM Generated Successfully in {format_option} format!")

            # Handling JSON-based SBOMs (CycloneDX, SPDX)
            if format_option in ["CycloneDX JSON", "SPDX JSON"]:
                try:
                    with open(output_file, "r") as f:
                        sbom_json = json.load(f)

                    if "components" in sbom_json and sbom_json["components"]:
                        st.subheader("📦 SBOM Components")

                        sbom_list = [
                            {
                                "Package": component.get("name", "N/A"),
                                "Version": component.get("version", "N/A"),
                                "Type": component.get("type", "N/A"),
                                "PURL": component.get("purl", "N/A"),
                            }
                            for component in sbom_json["components"]
                        ]

                        unique_sbom_list = {pkg["Package"]: pkg for pkg in sbom_list}.values()

                        # Search feature
                        search_term = st.text_input("🔎 Search for a Package", "")
                        filtered_sbom_list = [pkg for pkg in unique_sbom_list if search_term.lower() in pkg["Package"].lower()]
                        st.table(filtered_sbom_list if search_term else unique_sbom_list)

                    else:
                        st.warning("⚠️ No components found in the SBOM.")

                except json.JSONDecodeError:
                    st.error("❌ SBOM format is invalid. Try regenerating.")

            # Handling CSV output
            elif format_option == "CSV":
                try:
                    sbom_df = pd.read_csv(output_file, delimiter="\t" if "\t" in result.stdout else ",")
                    st.subheader("📦 SBOM Components (CSV Format)")
                    st.dataframe(sbom_df)  # Show CSV in table format

                except Exception as e:
                    st.error(f"❌ Error processing CSV file: {str(e)}")

            # Download button for SBOM
            with open(output_file, "r") as f:
                st.download_button(f"📥 Download SBOM ({format_option})", f, file_name=os.path.basename(output_file), mime="text/plain")

# 📌 Scan Vulnerabilities
if page == "Scan Vulnerabilities":
    st.subheader("⚠️ Scan for Vulnerabilities")

    if st.button("🔍 Start Vulnerability Scan"):
        scan_cmd = ["grype", f"sbom:{sbom_file}.cyclonedx", "-o", "json"]
        scan_result = subprocess.run(scan_cmd, capture_output=True, text=True)

        try:
            vuln_json = json.loads(scan_result.stdout)
            if "matches" in vuln_json and vuln_json["matches"]:
                st.subheader("🛡️ Vulnerability Scan Results")

                vuln_list = [
                    {
                        "Package": match["artifact"]["name"],
                        "Version": match["artifact"]["version"],
                        "Severity": match["vulnerability"]["severity"],
                        "CVE": match["vulnerability"]["id"]
                    }
                    for match in vuln_json["matches"]
                ]

                unique_vuln_list = {vuln["CVE"]: vuln for vuln in vuln_list}.values()

                sorted_vuln_list = sorted(unique_vuln_list, key=lambda x: x["Severity"], reverse=True)

                st.write("⚠️ High-severity vulnerabilities appear first.")
                st.table(sorted_vuln_list)

            else:
                st.info("✅ No known vulnerabilities found.")

        except json.JSONDecodeError:
            st.error("❌ Error parsing vulnerability scan results.")

# 📌 Compare Two SBOMs
if page == "Compare SBOMs":
    st.subheader("🔍 Compare Two SBOM Files")

    file1 = st.file_uploader("Upload First SBOM File", type=["json"])
    file2 = st.file_uploader("Upload Second SBOM File", type=["json"])

    if file1 and file2:
        sbom1 = json.load(file1)
        sbom2 = json.load(file2)

        sbom1_components = {comp["name"]: comp for comp in sbom1.get("components", [])}
        sbom2_components = {comp["name"]: comp for comp in sbom2.get("components", [])}

        added = [pkg for pkg in sbom2_components if pkg not in sbom1_components]
        removed = [pkg for pkg in sbom1_components if pkg not in sbom2_components]

        st.write("📌 **Added Components:**", added if added else "No new components")
        st.write("📌 **Removed Components:**", removed if removed else "No removed components")





