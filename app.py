import streamlit as st
import os
import json
import pandas as pd
import platform
import subprocess
import pefile
import requests
from sbom_compare import compare_sboms
from sbom_generator import generate_sbom
from sbom_parser import parse_sbom
from sbom_search import search_sbom

# Streamlit page config
st.set_page_config(page_title="SBOM Analyzer", page_icon="🔍", layout="wide")

st.markdown("""
<style>
.stApp { background: linear-gradient(135deg, #1f4037, #99f2c8); color: white; }
[data-testid="stSidebar"] { background: #1f2833; color: white; }
.stMarkdown h1, .stMarkdown h2, .stMarkdown h3 { color: #ffcc00; }
div.stButton > button { background-color: #008CBA; color: white; border-radius: 8px; }
div.stButton > button:hover { background-color: #005f73; }
</style>
""", unsafe_allow_html=True)

st.title("🔍 SBOM Analyzer - Generator, Parser, Comparator & Search")

# Sidebar inputs
st.sidebar.header("📂 Upload File")
file1 = st.sidebar.file_uploader("🆕 Upload First File", type=["exe", "json", "spdx", "csv", "xml"])
file2 = st.sidebar.file_uploader("📑 Upload Second File (Optional)", type=["exe", "json", "spdx", "csv", "xml"])
generate_button = st.sidebar.button("🔄 Generate SBOM")
compare_button = st.sidebar.button("🔍 Compare SBOMs")
search_button = st.sidebar.button("🔎 Search SBOM Components")
parse_button = st.sidebar.button("📜 Parse SBOM Data")

# Save uploaded files
def save_uploaded_file(uploaded_file, folder="uploaded_apps"):
    os.makedirs(folder, exist_ok=True)
    file_path = os.path.join(folder, uploaded_file.name)
    with open(file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    return file_path

# Extract metadata from EXE
def extract_file_metadata(file_path):
    compiler = "Unknown"
    arch = platform.architecture()[0]
    vendor = "Unknown"
    signature = "Not Available"

    if file_path.endswith(".exe"):
        try:
            pe = pefile.PE(file_path)
            if hasattr(pe, "OPTIONAL_HEADER"):
                compiler = f"Linker {pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}"
            if hasattr(pe, "FileInfo"):
                for fi in pe.FileInfo:
                    if hasattr(fi, "StringTable"):
                        for table in fi.StringTable:
                            for key, value in table.entries.items():
                                k = key.decode(errors="ignore").strip()
                                v = value.decode(errors="ignore").strip()
                                if k == "CompanyName" and v:
                                    vendor = v
        except:
            pass

    return {
        "Compiler": compiler,
        "Platform": arch,
        "Vendor": vendor,
        "Digital Signature": signature
    }

# Download SBOM
def download_sbom_report(sbom_data, filename="sbom.json"):
    sbom_json = json.dumps(sbom_data, indent=4)
    st.download_button("📥 Download SBOM", sbom_json, file_name=filename, mime="application/json")

# Display SBOM
def display_sbom_data(sbom_data, file_path):
    if not sbom_data:
        st.warning("⚠️ No SBOM data available.")
        return

    metadata = sbom_data.get("metadata", {})
    tools = metadata.get("tools", [])

    tool_used = tools[0].get("name") if tools and isinstance(tools[0], dict) else "Syft"
    tool_version = tools[0].get("version") if tools and isinstance(tools[0], dict) else sbom_data.get("specVersion", "1.6")
    software_name = metadata.get("component", {}).get("name", os.path.basename(file_path))
    vendor = metadata.get("supplier", {}).get("name", "Unknown")

    file_meta = extract_file_metadata(file_path)

    sbom_summary = {
        "Software Name": software_name,
        "Format": sbom_data.get("bomFormat", "CycloneDX"),
        "Version": sbom_data.get("specVersion", "1.6"),
        "Generated On": metadata.get("timestamp", "Unknown"),
        "Tool Used": tool_used,
        "Tool Version": tool_version,
        "Vendor": vendor if vendor != "Unknown" else file_meta["Vendor"],
        "Compiler": file_meta["Compiler"],
        "Platform": file_meta["Platform"],
        "Digital Signature": file_meta["Digital Signature"]
    }

    st.subheader("📄 SBOM Metadata")
    st.table(pd.DataFrame(sbom_summary.items(), columns=["Attribute", "Value"]))
    download_sbom_report(sbom_data, filename=f"{software_name}_SBOM.json")

    if "components" in sbom_data and isinstance(sbom_data["components"], list):
        st.subheader("🛠️ SBOM Components")
        st.dataframe(pd.DataFrame(sbom_data["components"]))
    else:
        st.warning("⚠️ No components found.")

# ✅ SBOM GENERATION
if generate_button and file1:
    file1_path = save_uploaded_file(file1)
    sbom_output = generate_sbom(file1_path)
    if sbom_output and isinstance(sbom_output, dict):
        display_sbom_data(sbom_output, file1_path)

# ✅ SBOM COMPARISON
if compare_button and file1 and file2:
    file1_path = save_uploaded_file(file1)
    file2_path = save_uploaded_file(file2)

    if not file1_path.endswith(".json") or not file2_path.endswith(".json"):
        st.error("❌ Please upload valid SBOM JSON files for comparison.")
    else:
        added, removed, error = compare_sboms(file1_path, file2_path)
        if error:
            st.error(f"❌ {error}")
        else:
            col1, col2 = st.columns(2)
            with col1:
                st.write("### ✅ Added Components")
                st.dataframe(pd.DataFrame(list(added), columns=["Added Components"])) if added else st.info("No components added.")
            with col2:
                st.write("### ❌ Removed Components")
                st.dataframe(pd.DataFrame(list(removed), columns=["Removed Components"])) if removed else st.info("No components removed.")

# ✅ SBOM PARSE
if parse_button and file1:
    file1_path = save_uploaded_file(file1)
    parsed = parse_sbom(file1_path)
    if parsed:
        st.subheader("📋 Parsed SBOM Components")
        st.dataframe(pd.DataFrame(parsed))

# ✅ SBOM SEARCH
if search_button and file1:
    file1_path = save_uploaded_file(file1)
    st.subheader("🔎 SBOM Component Search")
    all_components = search_sbom(file1_path)
    st.dataframe(pd.DataFrame(all_components))
    query = st.text_input("Enter component name or keyword:")
    if query:
        results = search_sbom(file1_path, query)
        st.dataframe(pd.DataFrame(results)) if results else st.warning("⚠️ No matches found.")

import requests

API_URL = "https://your-sbom-api.onrender.com"

def generate_sbom(file_path):
    """Calls the deployed SBOM API"""
    with open(file_path, "rb") as f:
        files = {"file": f}
        response = requests.post(f"{API_URL}/generate-sbom/", files=files)
        
    if response.status_code == 200:
        return response.json()
    else:
        st.error(f"❌ SBOM API Error: {response.text}")
        return None


