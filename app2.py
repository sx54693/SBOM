import streamlit as st
import os
import subprocess
import pandas as pd
import time
import json
import py7zr  # Ensure this is installed using `pip install py7zr`
from sbom_parser import load_sbom
from sbom_search import search_sbom
from sbom_compare import compare_sboms

# Set Streamlit page title
st.title("🛠️ SBOM Finder - Upload Software Applications & Generate SBOMs")

# Sidebar for file upload
st.sidebar.header("📂 Upload Software Application")
uploaded_file = st.sidebar.file_uploader(
    "Upload your application (EXE, APK, TAR.GZ, ZIP, etc.)",
    type=["exe", "apk", "tar.gz", "zip"]
)

sbom_df = pd.DataFrame()
UPLOAD_DIR = "uploaded_apps"
EXTRACT_DIR = "extracted_apps"
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(EXTRACT_DIR, exist_ok=True)

def process_uploaded_file(uploaded_file):
    """Handles file saving and extraction if needed."""
    safe_filename = uploaded_file.name.replace(" ", "_").replace("(", "").replace(")", "")
    file_path = os.path.join(UPLOAD_DIR, f"{int(time.time())}_{safe_filename}")

    try:
        with open(file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        st.success(f"✅ Uploaded file: `{uploaded_file.name}`")
    except PermissionError:
        st.error("❌ Permission denied! Try running the app as Administrator or changing folder permissions.")
        return None

    extracted_path = os.path.join(EXTRACT_DIR, safe_filename)
    os.makedirs(extracted_path, exist_ok=True)

    if uploaded_file.name.endswith((".exe", ".tar.gz", ".zip")):
        try:
            st.info("🔄 Extracting file contents... This may take a few moments.")
            extract_output = subprocess.run(["7z", "x", file_path, f"-o{extracted_path}", "-aoa"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            if extract_output.returncode == 0:
                st.success("✅ Extraction Completed Successfully!")
                st.text_area("📄 Extraction Output:", extract_output.stdout)
                return extracted_path
            else:
                st.error(f"❌ Extraction failed: {extract_output.stderr}")
        except Exception as e:
            st.error(f"❌ Extraction failed: {e}")
            return None
    return file_path

# Handle file upload for SBOM generation
if uploaded_file:
    scan_path = process_uploaded_file(uploaded_file)
    if scan_path:
        sbom_file = os.path.join(UPLOAD_DIR, "sbom_output.json")
        syft_command = f"syft dir:{scan_path} -o cyclonedx-json > {sbom_file}"
        process = subprocess.run(syft_command, shell=True, text=True)

        if process.returncode == 0 and os.path.exists(sbom_file):
            st.success("✅ SBOM Generated Successfully!")

            # Load and display the SBOM
            sbom_data = load_sbom(sbom_file)
            if sbom_data:
                sbom_df = pd.DataFrame(sbom_data.get("components", []))
                st.subheader("📜 SBOM Components")
                st.dataframe(sbom_df)

                # Search functionality
                query = st.text_input("🔍 Search SBOM Components by Name, Category, OS, or Type")
                if query:
                    search_results = search_sbom(sbom_data, query)
                    st.write("### 🔍 Search Results:")
                    for result in search_results:
                        st.write(f"- {result[0]} (Match: {result[1]}%)")
        else:
            st.error("❌ SBOM Generation Failed! Try extracting or installing the software before scanning.")

# SBOM Comparison Section
st.sidebar.header("🔍 Compare Two Applications or SBOMs")
file1 = st.sidebar.file_uploader("Upload First Application or SBOM File", type=["json", "csv", "spdx", "xml", "exe", "apk", "tar.gz", "zip"])
file2 = st.sidebar.file_uploader("Upload Second Application or SBOM File", type=["json", "csv", "spdx", "xml", "exe", "apk", "tar.gz", "zip"])

if file1 and file2:
    scan_path1 = process_uploaded_file(file1)
    scan_path2 = process_uploaded_file(file2)
    
    if scan_path1 and scan_path2:
        sbom1 = load_sbom(scan_path1 if scan_path1.endswith(".json") else None)
        sbom2 = load_sbom(scan_path2 if scan_path2.endswith(".json") else None)
        
        if sbom1 and sbom2:
            added, removed = compare_sboms(sbom1, sbom2)
            st.subheader("📊 SBOM Comparison")
            st.write("### 📌 Added Components:", list(added))
            st.write("### ❌ Removed Components:", list(removed))
        else:
            st.error("❌ Invalid SBOM files. Please upload valid JSON, CSV, SPDX, or XML SBOM files.")
    else:
        st.error("❌ One or both uploaded applications could not be processed. Ensure they are valid files.")

# SBOM Statistics
st.sidebar.markdown("**SBOM Statistics**")
if not sbom_df.empty:
    categories = sbom_df.groupby("type").size()
    st.sidebar.write("### 📊 Component Distribution by Type")
    st.sidebar.bar_chart(categories)

st.sidebar.info("Supports EXE, APK, TAR.GZ, ZIP files for SBOM generation and comparison. Now supports JSON, CSV, SPDX, and XML for SBOM comparison.")



