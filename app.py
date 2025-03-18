import streamlit as st
import os
import json
import pandas as pd
import hashlib
import subprocess
import shutil
import platform
import pefile
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

            # ✅ Extract Compiler Version (Handles Missing Fields)
            if hasattr(pe, "OPTIONAL_HEADER"):
                compiler = f"Linker {pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}"

            # ✅ Extract Vendor Information (Handles Key Errors)
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
                                    continue  # Ignore decoding errors

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

# Check Digital Signature using signtool.exe
def check_digital_signature(file_path):
    """Checks if an EXE file is digitally signed using signtool.exe"""

<<<<<<< HEAD
=======
    # Check if running on Windows
    if platform.system() != "Windows":
        return "⚠️ Signature Check Not Supported on Non-Windows Platforms"

>>>>>>> 72b1042e9665dae37c6c8ee540d4e8ead30edb15
    # ✅ Use Correct signtool.exe Path
    signtool_path = "C:\\Users\\cyria\\signtool.exe"

    if not os.path.exists(signtool_path):
        return "⚠️ Signature Check Tool Not Found"

    # ✅ Run signtool.exe and Check Output
    try:
        result = subprocess.run(
            [signtool_path, "verify", "/pa", file_path],
            capture_output=True, text=True, check=False
        )

        # ✅ Determine Signature Status
        if "Successfully verified" in result.stdout:
            return "✅ Signed"
        elif "No signature" in result.stdout or "is not signed" in result.stdout:
            return "❌ Not Signed"
        else:
            return f"⚠️ Unknown Signature Status: {result.stdout.strip()}"

    except Exception as e:
        return f"❌ Error Checking Signature: {str(e)}"

# Display SBOM Data
def display_sbom_data(sbom_data, file_path):
<<<<<<< HEAD
    """Extract and display SBOM metadata & components."""
=======
    """Extract and display SBOM metadata & components in Streamlit."""
>>>>>>> 72b1042e9665dae37c6c8ee540d4e8ead30edb15
    if not sbom_data:
        st.warning("⚠️ No SBOM data available.")
        return

<<<<<<< HEAD
    # Extract Metadata
    metadata = sbom_data.get("metadata", {})
    tools = metadata.get("tools", [])

    # ✅ Extract Tool Information
=======
    # ✅ Extract Metadata
    metadata = sbom_data.get("metadata", {})
    tools = metadata.get("tools", [])
    
>>>>>>> 72b1042e9665dae37c6c8ee540d4e8ead30edb15
    tool_used = "Unknown"
    tool_version = "Unknown"

    if isinstance(tools, list) and tools:
        for tool in tools:
            if isinstance(tool, dict):
                tool_used = tool.get("name", "Unknown")
                tool_version = tool.get("version", "Unknown")

<<<<<<< HEAD
    # Default to Syft if Tool Used is Unknown
    if tool_used == "Unknown":
        tool_used = "Syft"
        tool_version = sbom_data.get("specVersion", "Unknown")

    # Extract File Metadata
    file_metadata = extract_file_metadata(file_path)

    # ✅ Extract Vendor (From SBOM or EXE)
    vendor = file_metadata["Vendor"]
    if vendor == "Unknown" and "metadata" in sbom_data:
        vendor = sbom_data["metadata"].get("supplier", {}).get("name", "Unknown")
=======
    # ✅ Extract Vendor (From SBOM or EXE)
    vendor = sbom_data.get("metadata", {}).get("supplier", {}).get("name", "Unknown")
>>>>>>> 72b1042e9665dae37c6c8ee540d4e8ead30edb15

    # ✅ Extract Software Name
    software_name = sbom_data.get("metadata", {}).get("component", {}).get("name", "Unknown")

<<<<<<< HEAD
    # ✅ Extract Digital Signature
    digital_signature = file_metadata["Digital Signature"]

    # ✅ Display Metadata
    sbom_summary = {
        "Software Name": software_name,
        "Format": sbom_data.get("bomFormat", "Unknown"),
=======
    # ✅ Extract Digital Signature (Check If File Is Signed)
    digital_signature = sbom_data.get("Digital Signature", "Not Available")

    # ✅ Build SBOM Summary Table
    sbom_summary = {
        "Software Name": software_name,
        "Format": sbom_data.get("bomFormat", "CycloneDX"),
>>>>>>> 72b1042e9665dae37c6c8ee540d4e8ead30edb15
        "Version": sbom_data.get("specVersion", "Unknown"),
        "Generated On": metadata.get("timestamp", "Unknown"),
        "Tool Used": tool_used,
        "Tool Version": tool_version,
        "Vendor": vendor,
<<<<<<< HEAD
        "Compiler": file_metadata["Compiler"],
        "Platform": file_metadata["Platform"],
        "Digital Signature": digital_signature
    }

=======
        "Compiler": sbom_data.get("Compiler", "Unknown"),
        "Platform": sbom_data.get("Platform", "Unknown"),
        "Digital Signature": digital_signature
    }

    # ✅ Display SBOM Metadata as a Table
>>>>>>> 72b1042e9665dae37c6c8ee540d4e8ead30edb15
    st.subheader("📄 SBOM Metadata")
    st.table(pd.DataFrame(sbom_summary.items(), columns=["Attribute", "Value"]))

    # ✅ Display Components
<<<<<<< HEAD
    if "components" in sbom_data and isinstance(sbom_data["components"], list):
=======
    if "components" in sbom_data and isinstance(sbom_data["components"], list) and sbom_data["components"]:
>>>>>>> 72b1042e9665dae37c6c8ee540d4e8ead30edb15
        st.subheader("🛠️ SBOM Components")
        components_df = pd.DataFrame(sbom_data["components"])
        st.dataframe(components_df)
    else:
        st.warning("⚠️ No components found.")

# ✅ RUN SBOM GENERATION
if generate_button and file1:
    file1_path = save_uploaded_file(file1)
<<<<<<< HEAD
    sbom_output = generate_sbom(file1_path)
    
    if sbom_output:
        with open(sbom_output, "r", encoding="utf-8") as f:
            sbom_data = json.load(f)
        display_sbom_data(sbom_data, file1_path)
=======
    sbom_output = generate_sbom(file1_path)  # Corrected line

    if sbom_output:
        with open(sbom_output, "r", encoding="utf-8") as f:
            sbom_data = json.load(f)  # ✅ Load JSON Data
        display_sbom_data(sbom_data, file1_path)  # ✅ Pass SBOM Data to Function

>>>>>>> 72b1042e9665dae37c6c8ee540d4e8ead30edb15
