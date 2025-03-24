import streamlit as st
import os
import json
import pandas as pd
import requests

# Page Config
st.set_page_config(page_title="SBOM Analyzer", page_icon="🔍", layout="wide")

# UI Enhancements
st.markdown("""
    <style>
    .stApp { background: linear-gradient(135deg, #1f4037, #99f2c8); color: white; }
    [data-testid="stSidebar"] { background: #1f2833; color: white; }
    </style>
""", unsafe_allow_html=True)

# Title
st.title("🔍 SBOM Analyzer - Generator, Parser, Comparator & Search")

# Sidebar with Upload Option
st.sidebar.header("📂 Upload Software Application")
file1 = st.sidebar.file_uploader("🆕 Upload File", type=["exe"])

# Sidebar Button
generate_button = st.sidebar.button("🔄 Generate SBOM")

# Save Uploaded File
def save_uploaded_file(uploaded_file, folder="uploaded_apps"):
    if not os.path.exists(folder):
        os.makedirs(folder)
    file_path = os.path.join(folder, uploaded_file.name)
    with open(file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    return file_path

# Display SBOM Data
def display_sbom_data(sbom_data):
    metadata = sbom_data.get("metadata", {})
    sbom_summary = {
        "Software Name": metadata.get("component", {}).get("name", "Unknown"),
        "Format": sbom_data.get("bomFormat", "CycloneDX"),
        "Version": sbom_data.get("specVersion", "1.6"),
        "Generated On": metadata.get("timestamp", "N/A"),
        "Tool Used": metadata.get("tools", [{}])[0].get("name", "Syft"),
        "Tool Version": metadata.get("tools", [{}])[0].get("version", "1.0"),
        "Vendor": metadata.get("supplier", {}).get("name", "Unknown"),
        "Compiler": sbom_data.get("additionalProperties", {}).get("Compiler", "Unknown"),
        "Platform": sbom_data.get("additionalProperties", {}).get("Platform", "Unknown"),
        "Digital Signature": sbom_data.get("additionalProperties", {}).get("Digital Signature", "Not Available"),
    }

    st.subheader("📄 SBOM Metadata")
    st.table(pd.DataFrame(sbom_summary.items(), columns=["Attribute", "Value"]))

    st.download_button(
        label="📥 Download SBOM Report",
        data=json.dumps(sbom_data, indent=4),
        file_name=f"{sbom_summary['Software Name']}_SBOM.json",
        mime="application/json"
    )

    if "components" in sbom_data:
        st.subheader("🛠️ SBOM Components")
        st.dataframe(pd.DataFrame(sbom_data["components"]))
    else:
        st.warning("⚠️ No components found.")

API_URL = "https://your-sbom-api.onrender.com"

# Call SBOM Generation API
def generate_sbom(file_path):
    with open(file_path, "rb") as f:
        response = requests.post(f"{API_URL}/generate-sbom/", files={"file": f})
    if response.status_code == 200:
        return response.json()
    else:
        st.error(f"❌ SBOM API Error: {response.status_code}")
        return None

if generate_button and file1:
    file1_path = save_uploaded_file(file1)
    sbom_data = generate_sbom(file1_path)
    if sbom_data:
        display_sbom_data(sbom_data)
