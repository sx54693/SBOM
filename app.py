import streamlit as st
import os
import json
import requests
import pandas as pd
import platform
import pefile
import subprocess
from sbom_compare import compare_sboms
from sbom_generator import generate_sbom
from sbom_parser import parse_sbom
from sbom_search import search_sbom

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
st.title("🔍 SBOM Analyzer - Generator, Parser & Comparator")

# Sidebar with Upload Option
st.sidebar.header("📂 Upload Software Application or SBOM File")
file1 = st.sidebar.file_uploader("🆕 Upload First File", type=["exe", "json", "spdx", "csv", "xml"])

# Sidebar Buttons
generate_button = st.sidebar.button("🔄 Generate SBOM")

# API URL
API_URL = "https://your-render-api-url.onrender.com"

# Function to Save Files
def save_uploaded_file(uploaded_file, folder="uploaded_apps"):
    if not os.path.exists(folder):
        os.makedirs(folder)

    file_path = os.path.join(folder, uploaded_file.name)
    with open(file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    return file_path

# Function to Provide SBOM Report Download
def download_sbom_report(sbom_data, file_name="sbom_report.json"):
    sbom_json = json.dumps(sbom_data, indent=4)
    st.download_button(
        label="📥 Download SBOM Report",
        data=sbom_json,
        file_name=file_name,
        mime="application/json",
        key=file_name
    )

# Display SBOM Data
def display_sbom_data(sbom_data):
    if not sbom_data:
        st.warning("⚠️ No SBOM data available.")
        return

    metadata = sbom_data.get("metadata", {})
    tools = metadata.get("tools", [])

    tool_used = tools[0]["name"] if tools else "Syft"
    tool_version = tools[0]["version"] if tools else "Unknown"
    vendor = metadata.get("supplier", {}).get("name", "Unknown")
    software_name = metadata.get("component", {}).get("name", "Unknown")

    additional_props = sbom_data.get("additionalProperties", {})

    sbom_summary = {
        "Software Name": software_name,
        "Format": sbom_data.get("bomFormat", "Unknown"),
        "Version": sbom_data.get("specVersion", "Unknown"),
        "Generated On": metadata.get("timestamp", "N/A"),
        "Tool Used": tool_used,
        "Tool Version": tool_version,
        "Vendor": vendor,
        "Compiler": additional_props.get("Compiler", "Unknown"),
        "Platform": additional_props.get("Platform", "Unknown"),
        "Digital Signature": additional_props.get("Digital Signature", "Unknown"),
        "SHA256": additional_props.get("SHA256", "Unknown")
    }

    st.subheader("📄 SBOM Metadata")
    st.table(pd.DataFrame(sbom_summary.items(), columns=["Attribute", "Value"]))

    download_sbom_report(sbom_data, file_name=f"{software_name}_SBOM.json")

    if "components" in sbom_data:
        st.subheader("🛠️ SBOM Components")
        components_df = pd.DataFrame(sbom_data["components"])
        st.dataframe(components_df)
    else:
        st.warning("⚠️ No components found.")

# Generate SBOM through API call
if generate_button and file1:
    file1_path = save_uploaded_file(file1)

    with open(file1_path, "rb") as uploaded_file:
        files = {"file": uploaded_file}
        response = requests.post(f"{API_URL}/generate-sbom/", files=files)

    if response.status_code == 200:
        sbom_data = response.json()
        display_sbom_data(sbom_data)
    else:
        st.error(f"❌ SBOM API Error: {response.status_code} - {response.text}")
