import streamlit as st

def display_advanced_features():
    st.markdown("""
    ## 🚀 Advanced SBOM Tool Features

    This tool provides a range of advanced functionalities to support deep analysis and secure transparency of software components:
    
    ### 🔍 1. Smart SBOM Search
    - **Fuzzy/Partial Matching**: Quickly locate apps by name, category, platform, or type.
    - **Real-Time Filtering**: Dynamic search across uploaded and generated SBOMs.

    ### 📄 2. SBOM Display & Visualization
    - **Structured SBOM Viewer**: Presents formatted data (JSON/XML) with key component breakdowns.
    - **Metadata Extraction**: Includes tool version, architecture, vendor, permissions, and platform support.

    ### ⚖️ 3. Side-by-Side Comparison
    - **Component Comparison**: Shows added and removed libraries between two applications.
    - **APK Specifics**: Displays APK metadata, Smali packages, permissions, and native libraries.

    ### 📊 4. SBOM Statistics (Planned)
    - **Categorical Breakdown**: Stats by operating system, supplier, or app type.
    - **License Distribution**: Future support for SPDX-based license analytics.

    ### 💻 5. Platform Support
    - **Mobile & Desktop**: Supports `.apk`, `.exe`, and `.json` SBOM files.
    - **Format Compatibility**: Supports CycloneDX (JSON & XML), SPDX planned.

    ---
    
    ✨ **Coming Soon**:
    - Interactive charts (Pie/Bar) for package types
    - License and vulnerability reports
    - Live API search and database integration
    """)
