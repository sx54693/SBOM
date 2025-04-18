import streamlit as st
import os
import json
import pandas as pd
import subprocess
import platform
import pefile
from sbom_compare import compare_sboms
from sbom_generator import generate_sbom
from sbom_parser import parse_sbom
from sbom_search import search_sbom

API_URL = "https://sbom.onrender.com/generate-sbom/"
signtool_path = "C:\\Users\\cyria\\signtool.exe"

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

st.title("🔍 SBOM Analyzer - Generator, Parser & Comparator")

st.sidebar.header("📂 Upload Software Application or SBOM File")
file1 = st.sidebar.file_uploader("🆕 Upload First File", type=["exe", "apk", "json", "spdx", "csv", "xml"])
file2 = st.sidebar.file_uploader("📑 Upload Second File (Optional for Comparison)", type=["exe", "apk", "json", "spdx", "csv", "xml"])

generate_button = st.sidebar.button("🔄 Generate SBOM")
compare_button = st.sidebar.button("🔍 Compare SBOMs")

def save_uploaded_file(uploaded_file, folder="uploaded_apps"):
    if not os.path.exists(folder):
        os.makedirs(folder)
    file_path = os.path.join(folder, uploaded_file.name)
    with open(file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    os.chmod(file_path, 0o777)
    return file_path

def extract_with_7zip(file_path):
    try:
        result = subprocess.run(["7z", "l", file_path], capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return f"❌ 7-Zip Error: {str(e)}"

def extract_exe_libraries(file_path):
    try:
        pe = pefile.PE(file_path)
        imports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        imports.append(imp.name.decode('utf-8'))
        return imports
    except Exception as e:
        return [f"❌ Error extracting DLLs: {str(e)}"]

def parse_apk_with_apktool(file_path):
    try:
        out_dir = os.path.join("decoded_apks", os.path.basename(file_path).replace(".apk", ""))
        os.makedirs("decoded_apks", exist_ok=True)
        result = subprocess.run(["apktool", "d", "-f", file_path, "-o", out_dir], capture_output=True, text=True)
        log_output = result.stdout + "\n" + result.stderr

        packages = []
        smali_dir = os.path.join(out_dir, "smali")
        if os.path.exists(smali_dir):
            for root, dirs, files in os.walk(smali_dir):
                for file in files:
                    if file.endswith(".smali"):
                        package_path = os.path.relpath(root, smali_dir).replace(os.sep, ".")
                        if package_path not in packages:
                            packages.append(package_path)

        return log_output, packages
    except Exception as e:
        return f"❌ APKTool Error: {str(e)}", []

def display_sbom_data(sbom_data, file_path):
    metadata = sbom_data.get("metadata", {})
    tool_used = "Syft"
    tool_version = sbom_data.get("specVersion", "Unknown")
    vendor = metadata.get("supplier", {}).get("name", "Unknown")
    software_name = metadata.get("component", {}).get("name", os.path.basename(file_path))
    platform_info = platform.architecture()[0]

    sbom_summary = {
        "Software Name": software_name,
        "Format": sbom_data.get("bomFormat", "Unknown"),
        "Version": sbom_data.get("specVersion", "Unknown"),
        "Generated On": metadata.get("timestamp", "Unknown"),
        "Tool Used": tool_used,
        "Tool Version": tool_version,
        "Vendor": vendor,
        "Platform": platform_info
    }

    st.subheader("📄 SBOM Metadata")
    st.table(pd.DataFrame(sbom_summary.items(), columns=["Attribute", "Value"]))

    if "components" in sbom_data and isinstance(sbom_data["components"], list):
        st.subheader("🛠️ SBOM Components")
        components_df = pd.DataFrame(sbom_data["components"])
        st.dataframe(components_df)
    else:
        st.warning("⚠️ No components found.")

    with st.expander("📦 7-Zip Archive Contents"):
        st.code(extract_with_7zip(file_path))

    if file_path.endswith(".exe"):
        dlls = extract_exe_libraries(file_path)
        with st.expander("🧩 DLL Imports (.exe)"):
            st.write(dlls)

    if file_path.endswith(".apk"):
        log_output, packages = parse_apk_with_apktool(file_path)
        with st.expander("📦 APKTool Log Output"):
            st.code(log_output)
        with st.expander("📦 Smali Packages (.apk)"):
            st.write(packages)

if generate_button and file1:
    file1_path = save_uploaded_file(file1)
    sbom_output = generate_sbom(file1_path)
   if sbom_output and os.path.isfile(sbom_output):
    with open(sbom_output, "r", encoding="utf-8") as f:
        sbom_data = json.load(f)
    display_sbom_data(sbom_data, file1_path)
else:
    st.error("❌ SBOM generation failed. Please check if Syft is installed and accessible.")


if compare_button and file1 and file2:
    file1_path = save_uploaded_file(file1)
    file2_path = save_uploaded_file(file2)
    if not file1_path.endswith(".json"):
        file1_path = generate_sbom(file1_path)
    if not file2_path.endswith(".json"):
        file2_path = generate_sbom(file2_path)
    if file1_path and file2_path:
        added, removed, error = compare_sboms(file1_path, file2_path)
        if error:
            st.error(f"❌ {error}")
        else:
            col1, col2 = st.columns(2)
            with col1:
                st.write("### ✅ Added Components")
                st.dataframe(pd.DataFrame(list(added), columns=["Added Components"])) if added else st.info("No new components added.")
            with col2:
                st.write("### ❌ Removed Components")
                st.dataframe(pd.DataFrame(list(removed), columns=["Removed Components"])) if removed else st.info("No components removed.")
