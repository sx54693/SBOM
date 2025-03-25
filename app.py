import streamlit as st
import os
import json
import pandas as pd
import platform
import pefile
import requests
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
st.title("🔍 SBOM Analyzer - Generator, Parser, Comparator & Search")

# Sidebar with Upload Option
st.sidebar.header("📂 Upload Software Application or SBOM File")
file1 = st.sidebar.file_uploader("🆕 Upload First File", type=["exe", "json", "spdx", "csv", "xml"])
file2 = st.sidebar.file_uploader("📑 Upload Second File (Optional for Comparison)", type=["exe", "json", "spdx", "csv", "xml"])

# Sidebar Buttons
generate_button = st.sidebar.button("🔄 Generate SBOM")
compare_button = st.sidebar.button("🔍 Compare SBOMs")
search_button = st.sidebar.button("🔎 Search SBOM Components")
parse_button = st.sidebar.button("📜 Parse SBOM Data")

# Function to Save Files
def save_uploaded_file(uploaded_file, folder="uploaded_apps"):
    """Save uploaded file"""
    if not os.path.exists(folder):
        os.makedirs(folder)

    file_path = os.path.join(folder, uploaded_file.name)

    try:
        with open(file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        os.chmod(file_path, 0o777)
        return file_path
    except PermissionError:
        st.error(f"❌ Permission denied: {file_path}. Try running as administrator.")
        return None

# Extract Metadata from EXE
def extract_file_metadata(file_path):
    """Extracts compiler, platform, vendor, and digital signature safely"""
    compiler = "Unknown"
    arch = platform.architecture()[0]
    vendor = "Unknown"
    digital_signature = "Not Available"

    if file_path.endswith(".exe"):
        try:
            pe = pefile.PE(file_path)

            # ✅ Extract Compiler Version
            if hasattr(pe, "OPTIONAL_HEADER"):
                compiler = f"Linker {pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}"

            # ✅ Extract Vendor Information
            if hasattr(pe, "FileInfo"):
                for file_info in pe.FileInfo:
                    if hasattr(file_info, "StringTable"):
                        for entry in file_info.StringTable:
                            for key, value in entry.entries.items():
                                try:
                                    key_decoded = key.decode(errors="ignore").strip()
                                    value_decoded = value.decode(errors="ignore").strip()
                                    if key_decoded == "CompanyName" and value_decoded:
                                        vendor = value_decoded
                                except AttributeError:
                                    continue

            # ✅ Extract Digital Signature
            digital_signature = check_digital_signature(file_path)

        except Exception as e:
            compiler = "Error Extracting Compiler"
            vendor = f"Error Extracting Vendor: {str(e)}"
            digital_signature = "Error Extracting Digital Signature"

    return {
        "Compiler": compiler,
        "Platform": arch,
        "Vendor": vendor,
        "Digital Signature": digital_signature
    }

# Check Digital Signature
def check_digital_signature(file_path):
    # Skip on platforms that don't support signtool
    if not os.path.exists("C:\\Users\\cyria\\signtool.exe"):
        return "⚠️ Signature Check Not Available on Cloud"



    try:
        result = subprocess.run(
            [signtool_path, "verify", "/pa", file_path],
            capture_output=True, text=True, check=False
        )

        if "Successfully verified" in result.stdout:
            return "✅ Signed"
        elif "No signature" in result.stdout or "is not signed" in result.stdout:
            return "❌ Not Signed"
        else:
            return f"⚠️ Unknown Signature Status: {result.stdout.strip()}"

    except Exception as e:
        return f"❌ Error Checking Signature: {str(e)}"

# Function to Provide SBOM Report Download
def download_sbom_report(sbom_data, file_name="sbom_report.json"):
    """Allows users to download SBOM report in JSON format"""
    sbom_json = json.dumps(sbom_data, indent=4)
    
    st.download_button(
        label="📥 Download SBOM Report",
        data=sbom_json,
        file_name=file_name,
        mime="application/json"
    )

# Display SBOM Data
def display_sbom_data(sbom_data, file_path):
    """Extract and display SBOM metadata & components."""
    if not sbom_data:
        st.warning("⚠️ No SBOM data available.")
        return

    # Extract Metadata Safely
    metadata = sbom_data.get("metadata", {})
    tools = metadata.get("tools", [])

    # Tool Info
    tool_used = "Syft"
    tool_version = sbom_data.get("specVersion", "Unknown")
    if tools and isinstance(tools, list):
        first_tool = tools[0]
        tool_used = first_tool.get("name", tool_used)
        tool_version = first_tool.get("version", tool_version)

    # Software Name
    software_name = metadata.get("component", {}).get("name", None)
    if not software_name:
        software_name = os.path.basename(file_path)

    # Vendor
    vendor = metadata.get("supplier", {}).get("name", "Unknown")

    # Local metadata (compiler, platform, signature)
    file_metadata = extract_file_metadata(file_path)

    if vendor == "Unknown":
        vendor = file_metadata["Vendor"]

    # Compose SBOM Summary
    sbom_summary = {
        "Software Name": software_name,
        "Format": sbom_data.get("bomFormat", "CycloneDX"),
        "Version": sbom_data.get("specVersion", "Unknown"),
        "Generated On": metadata.get("timestamp", "N/A"),
        "Tool Used": tool_used,
        "Tool Version": tool_version,
        "Vendor": vendor,
        "Compiler": file_metadata["Compiler"],
        "Platform": file_metadata["Platform"],
        "Digital Signature": file_metadata["Digital Signature"]
    }

    st.subheader("📄 SBOM Metadata")
    st.table(pd.DataFrame(sbom_summary.items(), columns=["Attribute", "Value"]))

    # Download Button with Unique Key
    download_sbom_report(sbom_data, file_name=f"{software_name}_SBOM.json")

    # Display Components
    if "components" in sbom_data and isinstance(sbom_data["components"], list):
        st.subheader("🛠️ SBOM Components")
        components_df = pd.DataFrame(sbom_data["components"])
        st.dataframe(components_df)
    else:
        st.warning("⚠️ No components found.")


    # Download SBOM Report
def download_sbom_report(sbom_data, file_name="sbom_report.json"):
    """Allows users to download SBOM report in JSON format"""
    sbom_json = json.dumps(sbom_data, indent=4)

    st.download_button(
        label="📥 Download SBOM Report",
        data=sbom_json,
        file_name=file_name,
        mime="application/json",
        key=f"download-{file_name}"  # Unique key to prevent duplication error
    )


    # Components Display
    components = sbom_data.get("components", [])
    if components:
        st.subheader("🛠️ SBOM Components")
        st.dataframe(pd.DataFrame(components))
    else:
        st.warning("⚠️ No components found.")


# ✅ RUN SBOM GENERATION
# Corrected SBOM generation call
if generate_button and file1:
    file1_path = save_uploaded_file(file1)
    
    # Call your Render API function
    sbom_data = generate_sbom(file1_path)

    if sbom_data:
        # Directly display sbom_data, no file reading needed
        display_sbom_data(sbom_data, file1_path)
    else:
        st.error("❌ Failed to generate SBOM.")

     import requests
import streamlit as st

API_URL = "https://your-sbom-api.onrender.com/generate-sbom/"

def generate_sbom(file_path):
    with open(file_path, "rb") as f:
        files = {"file": f}
        response = requests.post(API_URL, files=files)
    
    if response.status_code == 200:
        # Directly return parsed JSON dict
        return response.json()
    else:
        st.error(f"❌ SBOM API Error: {response.status_code} - {response.text}")
        return None
