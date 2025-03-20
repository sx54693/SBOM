import streamlit as st
import os
import json
import pandas as pd
import platform
import pefile
import subprocess
from sbom_compare import compare_sboms
from sbom_generator import generate_sbom
from sbom_parser import parse_sbom
from sbom_search import search_sbom

# ✅ Streamlit Page Config
st.set_page_config(page_title="SBOM Analyzer", page_icon="🔍", layout="wide")

# ✅ UI Enhancements
st.markdown("""
    <style>
    .stApp { background: linear-gradient(135deg, #1f4037, #99f2c8); color: white; }
    [data-testid="stSidebar"] { background: #1f2833; color: white; }
    .stMarkdown h1, .stMarkdown h2, .stMarkdown h3 { color: #ffcc00; }
    div.stButton > button { background-color: #008CBA; color: white; border-radius: 8px; }
    div.stButton > button:hover { background-color: #005f73; }
    </style>
""", unsafe_allow_html=True)

# ✅ Page Title
st.title("🔍 SBOM Analyzer - Generator, Parser & Comparator")

# ✅ Sidebar - File Uploads
st.sidebar.header("📂 Upload Software Application or SBOM File")
file1 = st.sidebar.file_uploader("🆕 Upload First File", type=["exe", "json", "spdx", "csv", "xml"])
file2 = st.sidebar.file_uploader("📑 Upload Second File (Optional for Comparison)", type=["exe", "json", "spdx", "csv", "xml"])

# ✅ Sidebar - Action Buttons
generate_button = st.sidebar.button("🔄 Generate SBOM")
compare_button = st.sidebar.button("🔍 Compare SBOMs")
search_button = st.sidebar.button("🔎 Search SBOM Components")
parse_button = st.sidebar.button("📜 Parse SBOM Data")

# ✅ Function to Save Uploaded Files
def save_uploaded_file(uploaded_file, folder="uploaded_apps"):
    if not os.path.exists(folder):
        os.makedirs(folder)
    file_path = os.path.join(folder, uploaded_file.name)
    try:
        with open(file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        return file_path
    except PermissionError:
        st.error(f"❌ Permission denied: {file_path}. Try running as administrator.")
        return None

# ✅ Extract EXE Metadata
def extract_file_metadata(file_path):
    compiler, vendor, digital_signature = "Unknown", "Unknown", "Not Available"
    if file_path.endswith(".exe"):
        try:
            pe = pefile.PE(file_path)
            if hasattr(pe, "OPTIONAL_HEADER"):
                compiler = f"Linker {pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}"
            if hasattr(pe, "FileInfo"):
                for file_info in pe.FileInfo:
                    if hasattr(file_info, "StringTable"):
                        for entry in file_info.StringTable:
                            for key, value in entry.entries.items():
                                key_decoded = key.decode(errors="ignore").strip()
                                value_decoded = value.decode(errors="ignore").strip()
                                if key_decoded == "CompanyName" and value_decoded:
                                    vendor = value_decoded
            digital_signature = check_digital_signature(file_path)
        except Exception:
            pass
    return {"Compiler": compiler, "Platform": platform.architecture()[0], "Vendor": vendor, "Digital Signature": digital_signature}

# ✅ Check Digital Signature
def check_digital_signature(file_path):
    signtool_path = "C:\\Users\\cyria\\signtool.exe"
    if not os.path.exists(signtool_path):
        return "⚠️ Signature Check Tool Not Found"
    try:
        result = subprocess.run([signtool_path, "verify", "/pa", file_path], capture_output=True, text=True, check=False)
        if "Successfully verified" in result.stdout:
            return "✅ Signed"
        elif "No signature" in result.stdout or "is not signed" in result.stdout:
            return "❌ Not Signed"
        return "⚠️ Unknown Signature Status"
    except Exception:
        return "❌ Error Checking Signature"

# ✅ Function to Download SBOM Report
def download_sbom_report(sbom_data, file_name="sbom_report.json"):
    sbom_json = json.dumps(sbom_data, indent=4)
    st.download_button("📥 Download SBOM Report", data=sbom_json, file_name=file_name, mime="application/json")

# ✅ Display SBOM Metadata
def display_sbom_data(sbom_data, file_path):
    if not sbom_data:
        st.warning("⚠️ No SBOM data available.")
        return
    metadata = sbom_data.get("metadata", {})
    tools = metadata.get("tools", [])
    tool_used, tool_version = "Unknown", "Unknown"
    if isinstance(tools, list) and tools:
        for tool in tools:
            if isinstance(tool, dict):
                tool_used, tool_version = tool.get("name", "Unknown"), tool.get("version", "Unknown")
    file_metadata = extract_file_metadata(file_path)
    vendor = file_metadata["Vendor"] if file_metadata["Vendor"] != "Unknown" else sbom_data.get("metadata", {}).get("supplier", {}).get("name", "Unknown")
    software_name = sbom_data.get("metadata", {}).get("component", {}).get("name", "Unknown")
    digital_signature = file_metadata["Digital Signature"]

    # ✅ Display Metadata Table
    sbom_summary = {
        "Software Name": software_name,
        "Format": sbom_data.get("bomFormat", "Unknown"),
        "Version": sbom_data.get("specVersion", "Unknown"),
        "Generated On": metadata.get("timestamp", "Unknown"),
        "Tool Used": tool_used,
        "Tool Version": tool_version,
        "Vendor": vendor,
        "Compiler": file_metadata["Compiler"],
        "Platform": file_metadata["Platform"],
        "Digital Signature": digital_signature
    }
    st.subheader("📄 SBOM Metadata")
    st.table(pd.DataFrame(sbom_summary.items(), columns=["Attribute", "Value"]))

    # ✅ Allow Download
    download_sbom_report(sbom_data, file_name=f"{software_name}_SBOM.json")

    # ✅ Display Components
    if "components" in sbom_data and isinstance(sbom_data["components"], list):
        st.subheader("🛠️ SBOM Components")
        st.dataframe(pd.DataFrame(sbom_data["components"]))
    else:
        st.warning("⚠️ No components found.")

# ✅ Run SBOM Generation
if generate_button and file1:
    file1_path = save_uploaded_file(file1)
    if file1_path:
        sbom_output = generate_sbom(file1_path)
        if sbom_output:
            with open(sbom_output, "r", encoding="utf-8") as f:
                sbom_data = json.load(f)
            display_sbom_data(sbom_data, file1_path)
        else:
            st.error("❌ SBOM file was not generated.")

# ✅ Run SBOM Comparison
if compare_button and file1 and file2:
    st.subheader("📊 SBOM Comparison Results")
    file1_path, file2_path = save_uploaded_file(file1), save_uploaded_file(file2)
    file1_path = generate_sbom(file1_path) if not file1_path.endswith(".json") else file1_path
    file2_path = generate_sbom(file2_path) if not file2_path.endswith(".json") else file2_path
    added, removed, error = compare_sboms(file1_path, file2_path)
    if error:
        st.error(f"❌ {error}")
    else:
        st.write("✅ Added Components", pd.DataFrame(list(added), columns=["Added Components"]))
        st.write("❌ Removed Components", pd.DataFrame(list(removed), columns=["Removed Components"]))
