import streamlit as st
import os
import json
import pandas as pd
import platform
import pefile
import requests
import subprocess

# Page Config
st.set_page_config(page_title="SBOM Analyzer", page_icon="🔍", layout="wide")

# UI Enhancements
st.markdown("""
    <style>
    .stApp { background: linear-gradient(135deg, #1f4037, #99f2c8); color: white; }
    [data-testid="stSidebar"] { background: #1f2833; color: white; }
    .stMarkdown h1, .stMarkdown h2, .stMarkdown h3 { color: #ffcc00; }
    div.stButton > button { background-color: #008CBA; color: white; border-radius: 8px; }
    div.stButton > button:hover { background-color: #005f73; }
    </style>
""", unsafe_allow_html=True)

# Title
st.title("🔍 SBOM Analyzer - Generator, Parser, Comparator & Search")

# Sidebar Upload
st.sidebar.header("📂 Upload Software Application")
file1 = st.sidebar.file_uploader("🆕 Upload File", type=["exe"])

generate_button = st.sidebar.button("🔄 Generate SBOM")

API_URL = "https://your-sbom-api.onrender.com/generate-sbom/"  # Replace with your actual Render URL

# Save Uploaded File

def save_uploaded_file(uploaded_file, folder="uploaded_apps"):
    if not os.path.exists(folder):
        os.makedirs(folder)

    file_path = os.path.join(folder, uploaded_file.name)
    with open(file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())

    return file_path

# SBOM Generation via Render API

def generate_sbom_via_api(file_path):
    with open(file_path, "rb") as f:
        files = {"file": f}
        response = requests.post(API_URL, files=files)

    if response.status_code == 200:
        return response.json()
    else:
        st.error(f"❌ SBOM API Error: {response.status_code} - {response.text}")
        return None

# Display SBOM Data

def display_sbom_data(sbom_data):
    metadata = sbom_data.get("metadata", {})
    additional = sbom_data.get("additionalProperties", {})

    sbom_summary = {
        "Software Name": metadata.get("component", {}).get("name", "Unknown"),
        "Format": sbom_data.get("bomFormat", "CycloneDX"),
        "Version": sbom_data.get("specVersion", "Unknown"),
        "Generated On": metadata.get("timestamp", "Unknown"),
        "Tool Used": metadata.get("tools", [{}])[0].get("name", "Syft"),
        "Tool Version": metadata.get("tools", [{}])[0].get("version", "1.0"),
        "Vendor": metadata.get("supplier", {}).get("name", "Unknown"),
        "Compiler": additional.get("Compiler", "Unknown"),
        "Platform": additional.get("Platform", "Unknown"),
        "Digital Signature": additional.get("Digital Signature", "Unknown"),
        "SHA256": additional.get("SHA256", "Unknown")
    }

    st.subheader("📄 SBOM Metadata")
    st.table(pd.DataFrame(sbom_summary.items(), columns=["Attribute", "Value"]))

    # Download Button
    st.download_button(
        label="📥 Download SBOM Report",
        data=json.dumps(sbom_data, indent=4),
        file_name=f"{sbom_summary['Software Name']}_SBOM.json",
        mime="application/json",
        key=f"download-{sbom_summary['Software Name']}"
    )

    # Display Components
    components = sbom_data.get("components", [])
    if components:
        st.subheader("🛠️ SBOM Components")
        components_df = pd.DataFrame(components)
        st.dataframe(components_df)
    else:
        st.warning("⚠️ No components found.")

# Trigger SBOM Generation
if generate_button and file1:
    file_path = save_uploaded_file(file1)
    sbom_data = generate_sbom_via_api(file_path)

    if sbom_data:
        display_sbom_data(sbom_data)
