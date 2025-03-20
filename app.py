import streamlit as st
import requests
import pandas as pd
import json

# API URL (Ensure FastAPI is running)
API_URL = "https://sbom.onrender.com"

# Page Config
st.set_page_config(page_title="SBOM Analyzer", page_icon="🔍", layout="wide")

# Title
st.title("🔍 SBOM Analyzer - Generator & Viewer")

# Sidebar with Upload Option
file1 = st.sidebar.file_uploader("🆕 Upload Software File", type=["exe", "json", "spdx", "csv", "xml"])
generate_button = st.sidebar.button("🔄 Generate SBOM")

# ✅ Function to Call API for SBOM Generation
def generate_sbom(file):
    """Calls FastAPI backend to generate SBOM."""
    try:
        response = requests.post(f"{API_URL}/generate-sbom", files={"file": file})

        # Debugging: Show API response
        st.write("🔹 API Response Code:", response.status_code)
        st.write("🔹 API Response:", response.json())  

        if response.status_code == 200:
            return response.json()  # ✅ Return full response as a dictionary
        else:
            st.error(f"❌ API Error: {response.text}")
            return None
    except Exception as e:
        st.error(f"❌ Error calling API: {str(e)}")
        return None

# ✅ Function to Display SBOM Data
def display_sbom_data(sbom_data):
    """Extract and display SBOM components."""
    if not sbom_data:
        st.warning("⚠️ No SBOM data available.")
        return

    # ✅ Display Metadata
    software_name = sbom_data.get("filename", "Unknown Software")
    st.subheader(f"📄 SBOM Report for {software_name}")

    # ✅ Display Components
    components = sbom_data.get("sbom_components", [])
    if components:
        components_df = pd.DataFrame(components, columns=["Component Name"])
        st.dataframe(components_df)
    else:
        st.warning("⚠️ No components found.")

# ✅ SBOM GENERATION & DISPLAY
if generate_button and file1:
    with st.spinner("⏳ Generating SBOM..."):
        sbom_response = generate_sbom(file1)  # ✅ API Call

    if sbom_response:
        display_sbom_data(sbom_response)  # ✅ Display Components
    else:
        st.error("❌ SBOM data could not be retrieved.")
