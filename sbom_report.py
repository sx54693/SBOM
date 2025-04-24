# sbom_report.py

import json
import streamlit as st

def download_sbom_report(sbom_data, filename="sbom_report.json"):
    """
    Provides a Streamlit download button for the SBOM data in JSON format.
    
    :param sbom_data: Dictionary containing the SBOM.
    :param filename: Name of the JSON file to download.
    """
    if sbom_data:
        sbom_json = json.dumps(sbom_data, indent=4)
        st.download_button(
            label="📥 Download SBOM Report (JSON)",
            data=sbom_json,
            file_name=filename,
            mime="application/json"
        )
    else:
        st.warning("No SBOM data available to download.")
