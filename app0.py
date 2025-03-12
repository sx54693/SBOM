import os
import streamlit as st
import subprocess
import pandas as pd
from sbom_generator import generate_sbom
from sbom_parser import parse_sbom
from sbom_search import search_sbom
from sbom_compare import compare_sboms

# Streamlit Page Title
st.set_page_config(page_title="SBOM Finder", layout="wide")
st.title("📜 SBOM Generator & Comparator")

# Sidebar Navigation
page = st.sidebar.radio("🔍 Select Option", ["Generate SBOM", "Search Components", "Compare SBOMs"])

# Function to Save Uploaded Files
def save_uploaded_file(uploaded_file, folder="uploaded_apps"):
    if not os.path.exists(folder):
        os.makedirs(folder)
    file_path = os.path.join(folder, uploaded_file.name)
    with open(file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    return file_path

# 🚀 SBOM Generation Page
if page == "Generate SBOM":
    st.subheader("📂 Upload Your Software Application")
    uploaded_file = st.file_uploader("Upload EXE, APK, TAR.GZ, ZIP", type=["exe", "apk", "tar.gz", "zip"])

    if uploaded_file:
        file_path = save_uploaded_file(uploaded_file)
        st.success(f"✅ Uploaded file: {uploaded_file.name}")

        st.info("🔄 Generating SBOM... This may take a few moments.")
        sbom_path = generate_sbom(file_path)

        if sbom_path:
            st.success(f"✅ SBOM generated successfully for {uploaded_file.name}!")
            
            # Parse and display SBOM data
            sbom_data = parse_sbom(sbom_path)
            if sbom_data is not None:
                st.subheader("📜 SBOM Components")
                st.dataframe(sbom_data)  # Display structured SBOM data
            else:
                st.warning("⚠️ No components found, but displaying full SBOM for reference.")
        else:
            st.error("❌ SBOM generation failed. Please try again.")

# 🔎 SBOM Search Page
elif page == "Search Components":
    st.subheader("🔍 Search SBOM Components by Name, Category, OS, or Type")
    search_query = st.text_input("Enter component name, OS, or type:")
    
    if st.button("Search"):
        results = search_sbom(search_query)
        if results is not None and not results.empty:
            st.dataframe(results)
        else:
            st.warning("⚠️ No matching components found.")

# 🆚 SBOM Comparison Page
elif page == "Compare SBOMs":
    st.subheader("📂 Upload Two Software Applications for Comparison")

    file1 = st.file_uploader("Upload First Application (EXE, APK, TAR.GZ, ZIP, JSON, CSV, SPDX, XML)", type=["exe", "apk", "tar.gz", "zip", "json", "csv", "spdx", "xml"])
    file2 = st.file_uploader("Upload Second Application (EXE, APK, TAR.GZ, ZIP, JSON, CSV, SPDX, XML)", type=["exe", "apk", "tar.gz", "zip", "json", "csv", "spdx", "xml"])

    if file1 and file2:
        file1_path = save_uploaded_file(file1)
        file2_path = save_uploaded_file(file2)
        
        sbom1_path = generate_sbom(file1_path)
        sbom2_path = generate_sbom(file2_path)

        if sbom1_path and sbom2_path:
            comparison_results = compare_sboms(sbom1_path, sbom2_path)
            if comparison_results is not None and not comparison_results.empty:
                st.subheader("📊 SBOM Comparison Results")
                st.dataframe(comparison_results)
            else:
                st.warning("⚠️ No differences detected or comparison failed.")
        else:
            st.error("❌ Error generating SBOMs for comparison.")

