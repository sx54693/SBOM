import streamlit as st
import os
import json
import pandas as pd
from sbom_compare import compare_sboms
from sbom_generator import generate_sbom
from sbom_parser import parse_sbom
from sbom_search import search_sbom

# Page Config
st.set_page_config(page_title="SBOM Analyzer", page_icon="🔍", layout="wide")

# Custom Theme
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

# Sidebar
st.sidebar.header("📂 Upload Software Application or SBOM File")
file1 = st.sidebar.file_uploader("Upload First File (EXE, APK, TAR.GZ, ZIP, JSON, SPDX, CSV, XML)", 
                                 type=["exe", "apk", "tar.gz", "zip", "json", "spdx", "csv", "xml"])

file2 = st.sidebar.file_uploader("Upload Second File (Optional for Comparison)", 
                                 type=["exe", "apk", "tar.gz", "zip", "json", "spdx", "csv", "xml"])

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

# Function to Display SBOM Data in a Readable Table
def display_sbom_data(sbom_data):
    if not sbom_data:
        st.warning("⚠️ No SBOM data available.")
        return

    # Extract Key SBOM Details
    sbom_summary = {
        "Format": sbom_data.get("bomFormat", "Unknown"),
        "Version": sbom_data.get("specVersion", "Unknown"),
        "Serial Number": sbom_data.get("serialNumber", "Unknown"),
        "Generated On": sbom_data.get("metadata", {}).get("timestamp", "Unknown"),
        "Tool Used": sbom_data.get("metadata", {}).get("tools", {}).get("components", [{}])[0].get("name", "Unknown"),
        "Tool Version": sbom_data.get("metadata", {}).get("tools", {}).get("components", [{}])[0].get("version", "Unknown"),
        "Target File": sbom_data.get("metadata", {}).get("component", {}).get("name", "Unknown")
    }

    sbom_df = pd.DataFrame(list(sbom_summary.items()), columns=["Attribute", "Value"])
    st.table(sbom_df)  # Display SBOM details in a readable table

    # Display Components If Available
    if "components" in sbom_data and sbom_data["components"]:
        st.subheader("🛠️ SBOM Components")
        components_df = pd.DataFrame(sbom_data["components"])
        st.dataframe(components_df)
    else:
        st.warning("⚠️ No components found. Only metadata displayed.")

# **SBOM Generation**
if generate_button and file1:
    st.subheader("📜 SBOM Generation")
    file1_path = save_uploaded_file(file1)

    if file1_path:
        sbom_output = generate_sbom(file1_path)
        if sbom_output:
            st.success(f"✅ SBOM generated successfully for {file1.name}!")

            with open(sbom_output, "r", encoding="utf-8") as f:
                sbom_data = json.load(f)

            display_sbom_data(sbom_data)

            st.download_button(label="📥 Download SBOM", 
                               data=json.dumps(sbom_data, indent=2), 
                               file_name="sbom.json", 
                               mime="application/json")
        else:
            st.error("❌ SBOM generation failed. Please try again.")

# **SBOM Comparison**
if compare_button and file1 and file2:
    st.subheader("📊 SBOM Comparison Results")
    file1_path = save_uploaded_file(file1)
    file2_path = save_uploaded_file(file2)

    sbom1 = generate_sbom(file1_path)
    sbom2 = generate_sbom(file2_path)

    if sbom1 and sbom2:
        added, removed, error = compare_sboms(sbom1, sbom2)

        if error:
            st.error(f"❌ {error}")
        else:
            col1, col2 = st.columns(2)

            if added:
                with col1:
                    st.write("### ✅ Added Components")
                    st.dataframe(pd.DataFrame(list(added), columns=["Added Components"]))
            else:
                st.write("✅ No new components added.")

            if removed:
                with col2:
                    st.write("### ❌ Removed Components")
                    st.dataframe(pd.DataFrame(list(removed), columns=["Removed Components"]))
            else:
                st.write("✅ No components removed.")

# **SBOM Component Search**
if search_button and file1:
    st.subheader("🔎 SBOM Component Search")
    file1_path = save_uploaded_file(file1)
    if file1_path:
        all_components = search_sbom(file1_path)
        st.write("✅ **All Available SBOM Components:**")
        st.dataframe(pd.DataFrame(all_components))

        search_query = st.text_input("Enter component name, category, OS, or type:")

        if search_query:
            search_results = search_sbom(file1_path, search_query)
            if search_results:
                st.write("🔍 **Search Results:**")
                st.dataframe(pd.DataFrame(search_results))
            else:
                st.warning("⚠️ No matching components found.")

# **SBOM Data Parsing**
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
