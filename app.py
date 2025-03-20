import streamlit as st
import requests
import pandas as pd
import json
import os

# Page Configuration
st.set_page_config(page_title="SBOM Analyzer", page_icon="🔍", layout="wide")

# API Backend URL
API_URL = "https://sbom.onrender.com"

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
st.sidebar.header("📂 Upload Software Application")
uploaded_file = st.sidebar.file_uploader("🆕 Upload File", type=["exe", "json", "spdx", "csv", "xml"])
generate_button = st.sidebar.button("🔄 Generate SBOM")

# Generate SBOM from backend
if generate_button and uploaded_file:
    with st.spinner("⏳ Generating SBOM..."):
        try:
            # Make API call
            response = requests.post(
                f"{API_URL}/generate-sbom",
                files={"file": (uploaded_file.name, uploaded_file.getvalue(), uploaded_file.type)}
            )

            if response.status_code == 200:
                sbom_data = response.json()
                
                # SBOM Metadata Display
                st.subheader(f"📄 SBOM Report for {sbom_data.get('filename', 'N/A')}")

                # Extract SBOM components from response
                components = sbom_data.get("sbom_components", [])

                if components:
                    st.subheader("🛠️ SBOM Components")
                    components_df = pd.DataFrame(components, columns=["Components"])
                    st.dataframe(components_df)

                    # Download SBOM
                    sbom_json = json.dumps(sbom_data, indent=4)
                    st.download_button(
                        label="📥 Download SBOM Report",
                        data=sbom_json,
                        file_name=f"{os.path.splitext(uploaded_file.name)[0]}_sbom.json",
                        mime="application/json"
                    )
                else:
                    st.warning("⚠️ No SBOM components found.")

            else:
                st.error(f"❌ API Error: {response.status_code} - {response.text}")

        except Exception as e:
            st.error(f"❌ Error generating SBOM: {str(e)}")

elif generate_button and not uploaded_file:
    st.error("❌ Please upload a file to generate SBOM.")
