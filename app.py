import streamlit as st
import os
import json
import requests
import pandas as pd
import platform
import subprocess
import pefile

# API URL (Make sure this is running)
API_URL = "https://sbom.onrender.com"

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

# ✅ Function to Call API for SBOM Generation
def generate_sbom(file):
    """Calls the FastAPI backend to generate SBOM."""
    try:
        response = requests.post(f"{API_URL}/generate-sbom", files={"file": file})
        
        # Debugging: Print API response
        st.write("🔹 API Response Code:", response.status_code)
        st.write("🔹 API Response:", response.text)  # Print full API response
        
        if response.status_code == 200:
            return response.json().get("sbom_path")  # ✅ Get SBOM path from response
        else:
            st.error(f"❌ API Error: {response.text}")
            return None
    except Exception as e:
        st.error(f"❌ Error calling API: {str(e)}")
        return None

# ✅ Function to Display SBOM Data
def display_sbom_data(sbom_data):
    """Extract and display SBOM metadata & components."""
    if not sbom_data:
        st.warning("⚠️ No SBOM data available.")
        return

    # Extract Metadata
    metadata = sbom_data.get("metadata", {})
    software_name = metadata.get("component", {}).get("name", "Unknown")
    
    # ✅ Display Metadata
    sbom_summary = {
        "Software Name": software_name,
        "Format": sbom_data.get("bomFormat", "Unknown"),
        "Version": sbom_data.get("specVersion", "Unknown"),
        "Generated On": metadata.get("timestamp", "Unknown"),
    }

    st.subheader("📄 SBOM Metadata")
    st.table(pd.DataFrame(sbom_summary.items(), columns=["Attribute", "Value"]))

    # ✅ Display Components
    if "components" in sbom_data:
        st.subheader("🛠️ SBOM Components")
        components_df = pd.DataFrame(sbom_data["components"])
        st.dataframe(components_df)
    else:
        st.warning("⚠️ No components found.")

# ✅ SBOM GENERATION & DISPLAY
if generate_button and file1:
    with st.spinner("⏳ Generating SBOM..."):
        sbom_output = generate_sbom(file1)

    if sbom_output:
        with open(sbom_output, "r", encoding="utf-8") as f:
            sbom_data = json.load(f)  # ✅ Read SBOM Data
        
        display_sbom_data(sbom_data)  # ✅ Show SBOM
    else:
        st.error("❌ SBOM file was not generated.")



import streamlit as st

API_URL = "https://sbom.onrender.com"

def generate_sbom(file):
    """Calls the FastAPI backend to generate SBOM."""
    try:
        response = requests.post(f"{API_URL}/generate-sbom", files={"file": file})
        
        # Debugging: Print API response
        st.write("🔹 API Response Code:", response.status_code)
        st.write("🔹 API Response:", response.text)  # Print full API response
        
        return response.json()
    except Exception as e:
        st.error(f"❌ Error calling API: {str(e)}")
with open(sbom_output, "r", encoding="utf-8") as f:
    sbom_data = json.load(f)  # No extra spaces/tabs
display_sbom_data(sbom_data, file1_path)  # Ensure consistent indentation

API_URL = "https://sbom.onrender.com"

