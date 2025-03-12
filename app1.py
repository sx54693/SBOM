import streamlit as st
import os
import json
import pandas as pd
from sbom_compare import compare_sboms
from sbom_generator import generate_sbom
from sbom_parser import parse_sbom
from sbom_search import search_sbom
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
        return file_path
    except PermissionError:
        st.error(f"❌ Permission denied: {file_path}. Try running as administrator.")
        return None

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
    if file1_path:
        sbom_output = generate_sbom(file1_path)
        if sbom_output:
            st.success(f"✅ SBOM generated successfully for {file1.name}!")
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




