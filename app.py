import streamlit as st
import os
import json
import pandas as pd
import platform
import pefile
import requests
import subprocess

# Streamlit page configuration
st.set_page_config(page_title="SBOM Analyzer", page_icon="🔍", layout="wide")

# Title and UI enhancements
st.title("🔍 SBOM Analyzer - Generator, Parser & Comparator")

# Sidebar Upload
st.sidebar.header("📂 Upload Software Application or SBOM File")
file1 = st.sidebar.file_uploader("🆕 Upload First File", type=["exe", "json", "spdx", "csv", "xml"])

# Sidebar Button
generate_button = st.sidebar.button("🔄 Generate SBOM")

# Function to Save Files
def save_uploaded_file(uploaded_file, folder="uploaded_apps"):
    if not os.path.exists(folder):
        os.makedirs(folder)

    file_path = os.path.join(folder, uploaded_file.name)

    with open(file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())

    return file_path

# Metadata Extraction for EXE
def extract_file_metadata(file_path):
    metadata = {
        "Compiler": "Unknown",
        "Platform": platform.architecture()[0],
        "Vendor": "Unknown",
        "Digital Signature": "⚠️ Signature Check Not Available on Cloud"
    }

    if file_path.endswith(".exe"):
        try:
            pe = pefile.PE(file_path)
            if hasattr(pe, "OPTIONAL_HEADER"):
                metadata["Compiler"] = f"Linker {pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}"
            if hasattr(pe, "FileInfo"):
                for file_info in pe.FileInfo:
                    if hasattr(file_info, "StringTable"):
                        for entry in file_info.StringTable:
                            for key, value in entry.entries.items():
                                if key.decode(errors="ignore").strip() == "CompanyName":
                                    metadata["Vendor"] = value.decode(errors="ignore").strip()
        except Exception as e:
            st.warning(f"Metadata extraction error: {e}")

    return metadata

# Display SBOM Data and Components
def display_sbom_data(sbom_data, file_path):
    if not sbom_data:
        st.error("⚠️ No SBOM data available.")
        return

    metadata = sbom_data.get("metadata", {})

    software_name = metadata.get("component", {}).get("name", os.path.basename(file_path))
    vendor = metadata.get("supplier", {}).get("name", "Unknown")

    file_metadata = extract_file_metadata(file_path)

    sbom_summary = {
        "Software Name": software_name,
        "Format": sbom_data.get("bomFormat", "CycloneDX"),
        "Version": sbom_data.get("specVersion", "Unknown"),
        "Generated On": metadata.get("timestamp", "N/A"),
        "Tool Used": metadata.get("tools", [{}])[0].get("name", "Syft"),
        "Tool Version": metadata.get("tools", [{}])[0].get("version", "Unknown"),
        "Vendor": vendor if vendor != "Unknown" else file_metadata["Vendor"],
        "Compiler": file_metadata["Compiler"],
        "Platform": file_metadata["Platform"],
        "Digital Signature": file_metadata["Digital Signature"]
    }

    st.subheader("📄 SBOM Metadata")
    st.table(pd.DataFrame(sbom_summary.items(), columns=["Attribute", "Value"]))

    st.download_button(
        label="📥 Download SBOM Report",
        data=json.dumps(sbom_data, indent=4),
        file_name=f"{software_name}_SBOM.json",
        mime="application/json",
        key=f"download-{software_name}"
    )

    components = sbom_data.get("components", [])
    if components:
        st.subheader("🛠️ SBOM Components")
        st.dataframe(pd.DataFrame(components))
    else:
        st.warning("⚠️ No components found.")

# Backend API Integration (Replace URL with your Render URL)
API_URL = "https://your-render-api.onrender.com/generate-sbom/"

def generate_sbom_via_api(file_path):
    with open(file_path, "rb") as f:
        response = requests.post(API_URL, files={"file": f})

    if response.status_code == 200:
        return response.json()
    else:
        st.error(f"❌ SBOM API Error: {response.status_code} - {response.text}")
        return None

# SBOM Generation via API
if generate_button and file1:
    file_path = save_uploaded_file(file1)
    sbom_data = generate_sbom_via_api(file_path)

    if sbom_data:
        display_sbom_data(sbom_data, file_path)
