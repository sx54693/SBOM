import streamlit as st
import os
import json
import pandas as pd
import requests

# Page Configuration
st.set_page_config(page_title="SBOM Analyzer", page_icon="🔍", layout="wide")

# UI Styling
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
st.sidebar.header("📂 Upload Software or SBOM")
file1 = st.sidebar.file_uploader("🆕 Upload First File", type=["exe", "json", "spdx", "csv", "xml"])
file2 = st.sidebar.file_uploader("📑 Upload Second File (For Comparison)", type=["exe", "json", "spdx", "csv", "xml"])

# Buttons
generate_button = st.sidebar.button("🔄 Generate SBOM")
compare_button = st.sidebar.button("🔍 Compare SBOMs")
search_button = st.sidebar.button("🔎 Search Components")
parse_button = st.sidebar.button("📜 Parse SBOM")

# API Backend
API_URL = "https://sbom.onrender.com"

# Save Uploaded File
def save_uploaded_file(uploaded_file, folder="uploaded_apps"):
    os.makedirs(folder, exist_ok=True)
    file_path = os.path.join(folder, uploaded_file.name)
    with open(file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    return file_path

# Display SBOM Data
def display_sbom_data(sbom_data):
    if not sbom_data:
        st.warning("⚠️ No SBOM data available.")
        return

    st.subheader("📄 SBOM Metadata")
    metadata_df = pd.DataFrame(sbom_data.get("metadata", {}).items(), columns=["Attribute", "Value"])
    st.table(metadata_df)

    components = sbom_data.get("components", [])
    if components:
        st.subheader("🛠️ SBOM Components")
        st.dataframe(pd.DataFrame(components))
    else:
        st.info("⚠️ No components found.")

    st.download_button(
        label="📥 Download SBOM JSON",
        data=json.dumps(sbom_data, indent=4),
        file_name="sbom_report.json",
        mime="application/json"
    )

# Generate SBOM
if generate_button and file1:
    file1_path = save_uploaded_file(file1)

    with open(file1_path, 'rb') as file_data:
        response = requests.post(f"{API_URL}/generate-sbom", files={"file": file_data})

    if response.status_code == 200:
        sbom_data = response.json()
        display_sbom_data(sbom_data)
    else:
        st.error(f"❌ API Error: {response.text}")

# Compare SBOMs
if compare_button and file1 and file2:
    file1_path = save_uploaded_file(file1)
    file2_path = save_uploaded_file(file2)

    files = {
        "file1": open(file1_path, 'rb'),
        "file2": open(file2_path, 'rb')
    }
    response = requests.post(f"{API_URL}/compare-sboms", files=files)

    if response.status_code == 200:
        result = response.json()
        st.subheader("📊 SBOM Comparison Results")
        col1, col2 = st.columns(2)

        with col1:
            st.markdown("### ✅ Added Components")
            st.dataframe(pd.DataFrame(result.get("added", []), columns=["Component"]))

        with col2:
            st.markdown("### ❌ Removed Components")
            st.dataframe(pd.DataFrame(result.get("removed", []), columns=["Component"]))
    else:
        st.error(f"❌ API Error: {response.text}")

# Search SBOM Components
if search_button and file1:
    file1_path = save_uploaded_file(file1)
    search_term = st.sidebar.text_input("Enter Component to Search")

    if search_term:
        with open(file1_path, 'rb') as file_data:
            response = requests.post(f"{API_URL}/search-sbom", files={"file": file_data}, data={"query": search_term})

        if response.status_code == 200:
            search_results = response.json().get("results", [])
            st.subheader("🔎 Search Results")
            st.dataframe(pd.DataFrame(search_results, columns=["Matching Components"]))
        else:
            st.error(f"❌ API Error: {response.text}")
    else:
        st.info("⚠️ Enter a component name to search.")

# Parse SBOM Data
if parse_button and file1:
    file1_path = save_uploaded_file(file1)

    with open(file1_path, 'rb') as file_data:
        response = requests.post(f"{API_URL}/parse-sbom", files={"file": file_data})

    if response.status_code == 200:
        parsed_data = response.json()
        st.subheader("📜 Parsed SBOM Data")
        st.json(parsed_data)
    else:
        st.error(f"❌ API Error: {response.text}")
