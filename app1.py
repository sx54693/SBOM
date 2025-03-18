import streamlit as st
import os
import json
import pandas as pd
<<<<<<< HEAD
import hashlib
import subprocess
import shutil
import platform
import pefile
=======
>>>>>>> 72b1042e9665dae37c6c8ee540d4e8ead30edb15
from sbom_compare import compare_sboms
from sbom_generator import generate_sbom
from sbom_parser import parse_sbom
from sbom_search import search_sbom
<<<<<<< HEAD

# Page Config with Dark Mode UI
st.set_page_config(page_title="SBOM Analyzer", page_icon="🔍", layout="wide")

# Custom Theme & UI Enhancements
st.markdown("""
    <style>
    .stApp { background: linear-gradient(135deg, #1f4037, #99f2c8); color: white; }
    [data-testid="stSidebar"] { background: #1f2833; color: white; }
    .stMarkdown h1, .stMarkdown h2, .stMarkdown h3 { color: #ffcc00; }
    div.stButton > button { background-color: #008CBA; color: white; border-radius: 8px; }
    div.stButton > button:hover { background-color: #005f73; }
    table { background-color: #2c3e50; color: white; border-radius: 8px; }
    </style>
""", unsafe_allow_html=True)

# Title
st.title("🔍 SBOM Analyzer - Generator, Parser & Comparator")

# Sidebar with Icons
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
=======
from fuzzywuzzy import process

def save_uploaded_file(uploaded_file, folder="uploaded_apps"):
    """Save uploaded file to the specified folder with proper permissions."""
    if not os.path.exists(folder):
        os.makedirs(folder)
    file_path = os.path.join(folder, uploaded_file.name)
    
    try:
        with open(file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        os.chmod(file_path, 0o777)  # Ensure correct permissions
>>>>>>> 72b1042e9665dae37c6c8ee540d4e8ead30edb15
        return file_path
    except PermissionError:
        st.error(f"❌ Permission denied: {file_path}. Try running as administrator.")
        return None

<<<<<<< HEAD
# Extract Metadata from EXE
def extract_file_metadata(file_path):
    """Extracts compiler, platform, vendor, and digital signature"""
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

            # ✅ Extract Vendor Information (EXE Metadata)
            if hasattr(pe, "FileInfo"):
                for file_info in pe.FileInfo:
                    if hasattr(file_info, "StringTable"):
                        for entry in file_info.StringTable:
                            for key, value in entry.entries.items():
                                key_decoded = key.decode(errors="ignore").strip()
                                value_decoded = value.decode(errors="ignore").strip()
                                if key_decoded == "CompanyName" and value_decoded:
                                    vendor = value_decoded

            # ✅ Extract Digital Signature
            signtool_path = shutil.which("signtool.exe")
            if signtool_path:
                result = subprocess.run([signtool_path, "verify", "/pa", file_path], capture_output=True, text=True)
                if "Successfully verified" in result.stdout:
                    digital_signature = "Signed"
                elif "No signature" in result.stdout or "is not signed" in result.stdout:
                    digital_signature = "Not Signed"
                else:
                    digital_signature = f"Unknown Signature Status: {result.stdout.strip()}"

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

# Display SBOM Data
def display_sbom_data(sbom_data, file_path):
    """Extract and display SBOM metadata & components."""
    if not sbom_data:
        st.warning("⚠️ No SBOM data available.")
        return

    # Extract Metadata
    metadata = sbom_data.get("metadata", {})
    tools = metadata.get("tools", [])

    # ✅ Extract Tool Information
    tool_used = "Unknown"
    tool_version = "Unknown"

    if isinstance(tools, list) and tools:
        for tool in tools:
            if isinstance(tool, dict):
                tool_used = tool.get("name", "Unknown")
                tool_version = tool.get("version", "Unknown")

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

    # ✅ Extract Software Name
    software_name = sbom_data.get("metadata", {}).get("component", {}).get("name", "Unknown")

    # ✅ Extract Digital Signature
    digital_signature = file_metadata["Digital Signature"]

    # SBOM Summary Table
    sbom_summary = {
        "Software Name": software_name,
        "Format": sbom_data.get("bomFormat", "Unknown"),
        "Version": sbom_data.get("specVersion", "Unknown"),
        "Serial Number": sbom_data.get("serialNumber", "Unknown"),
        "Generated On": metadata.get("timestamp", "Unknown"),
        "Tool Used": tool_used,
        "Tool Version": tool_version,
        "Target File": metadata.get("component", {}).get("name", "Unknown"),
        "Vendor": vendor,
        "Compiler": file_metadata["Compiler"],
        "Platform": file_metadata["Platform"],
        "Digital Signature": digital_signature
    }

    # ✅ Display Metadata with Better Styling
    st.subheader("📄 SBOM Metadata")
    sbom_df = pd.DataFrame(list(sbom_summary.items()), columns=["Attribute", "Value"])
    st.table(sbom_df)

    # ✅ Display Components with Enhanced UI
    if "components" in sbom_data and isinstance(sbom_data["components"], list):
        st.subheader("🛠️ SBOM Components")
        components_df = pd.DataFrame(sbom_data["components"])
        st.dataframe(components_df)
    else:
        st.warning("⚠️ No components found.")

# Generate SBOM
if generate_button and file1:
    st.subheader("📜 SBOM Generation")
    file1_path = save_uploaded_file(file1)

=======
# Streamlit App
st.title("🔍 SBOM Generator, Parser, Search & Comparator")

st.sidebar.header("📂 Upload Your Software Application or SBOM File")
file1 = st.sidebar.file_uploader("Upload First File (EXE, APK, TAR.GZ, ZIP, JSON, SPDX, CSV, XML)",
                                 type=["exe", "apk", "tar.gz", "zip", "json", "spdx", "csv", "xml"])
file2 = st.sidebar.file_uploader("Upload Second File (Optional for Comparison)",
                                 type=["exe", "apk", "tar.gz", "zip", "json", "spdx", "csv", "xml"])

generate_button = st.sidebar.button("🔄 Generate SBOM")
compare_button = st.sidebar.button("🔍 Compare SBOMs")
search_button = st.sidebar.button("🔎 Search SBOM Components")
parse_button = st.sidebar.button("📜 Parse SBOM Data")

if generate_button and file1:
    st.subheader("📜 SBOM Generation")
    file1_path = save_uploaded_file(file1)
>>>>>>> 72b1042e9665dae37c6c8ee540d4e8ead30edb15
    if file1_path:
        sbom_output = generate_sbom(file1_path)
        if sbom_output:
            st.success(f"✅ SBOM generated successfully for {file1.name}!")
<<<<<<< HEAD

            with open(sbom_output, "r", encoding="utf-8") as f:
                sbom_data = json.load(f)

            display_sbom_data(sbom_data, file1_path)

            st.download_button(label="📥 Download SBOM", 
                               data=json.dumps(sbom_data, indent=2), 
                               file_name="sbom.json", 
                               mime="application/json")
        else:
            st.error("❌ SBOM generation failed. Please try again.")
=======
            with open(sbom_output, "r", encoding="utf-8") as f:
                sbom_data = json.load(f)
            
            if "components" in sbom_data and sbom_data["components"]:
                df = pd.DataFrame(sbom_data["components"])
                st.write("### 📜 SBOM Components")
                st.dataframe(df)  # Display SBOM as a readable table
            else:
                st.warning("⚠️ No components found, displaying key SBOM details.")
                sbom_summary = {
                    "Format": sbom_data.get("bomFormat", "Unknown"),
                    "Version": sbom_data.get("specVersion", "Unknown"),
                    "Serial Number": sbom_data.get("serialNumber", "Unknown"),
                    "Generated On": sbom_data.get("metadata", {}).get("timestamp", "Unknown"),
                    "Tool Used": sbom_data.get("metadata", {}).get("tools", {}).get("components", [{}])[0].get("name", "Unknown"),
                    "Tool Version": sbom_data.get("metadata", {}).get("tools", {}).get("components", [{}])[0].get("version", "Unknown"),
                    "Target File": sbom_data.get("metadata", {}).get("component", {}).get("name", "Unknown")
                }
                summary_df = pd.DataFrame([sbom_summary])
                st.dataframe(summary_df)  # Show SBOM summary in table format
            
            st.download_button(label="📥 Download SBOM", data=json.dumps(sbom_data, indent=2), file_name="sbom.json", mime="application/json")
        else:
            st.error("❌ SBOM generation failed. Please try again.")

if compare_button and file1 and file2:
    st.subheader("📊 SBOM Comparison Results")
    file1_path = save_uploaded_file(file1)
    file2_path = save_uploaded_file(file2)
    
    if file1_path and file2_path:
        print(f"🔍 Running SBOM comparison on: {file1_path} vs {file2_path}")
        added, removed, error = compare_sboms(file1_path, file2_path)
        
        if error:
            st.error(f"❌ {error}")
            print(f"❌ SBOM Comparison Error: {error}")
        else:
            if not added and not removed:
                st.info("✅ No differences found between the two SBOMs.")
                print("✅ No differences detected.")
            else:
                st.write("### ✅ Added Components:")
                st.dataframe(pd.DataFrame(added, columns=["Added Components"]))
                st.write("### ❌ Removed Components:")
                st.dataframe(pd.DataFrame(removed, columns=["Removed Components"]))
                print(f"🟢 Added: {added}")
                print(f"🔴 Removed: {removed}")


if search_button and file1:
    st.subheader("🔎 SBOM Component Search")
    file1_path = save_uploaded_file(file1)
    if file1_path:
        all_components = search_sbom(file1_path, "")
        st.write("✅ **All Available SBOM Components:**")
        st.dataframe(pd.DataFrame(all_components))  # Show all components
        
        search_query = st.text_input("Enter component name, category, OS, or type:")
        
        if search_query:
            search_results = search_sbom(file1_path, search_query)
            
            if search_results:
                st.write("🔍 **Search Results:**")
                st.dataframe(pd.DataFrame(search_results))
            else:
                st.warning("⚠️ No matching components found. Try a different keyword.")

if parse_button and file1:
    st.subheader("📜 SBOM Data Parsing")
    file1_path = save_uploaded_file(file1)
    if file1_path:
        parsed_data = parse_sbom(file1_path)
        if parsed_data:
            st.write("### 📄 Parsed SBOM Data")
            st.dataframe(pd.DataFrame(parsed_data))
        else:
            st.error("❌ Failed to parse SBOM data.")




>>>>>>> 72b1042e9665dae37c6c8ee540d4e8ead30edb15
