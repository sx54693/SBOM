import streamlit as st
import os
import json
import pandas as pd
import platform
import pefile
import subprocess
import requests

# If you still use these local modules, keep these:
from sbom_compare import compare_sboms
# from sbom_parser import parse_sbom  # If you actually use parse_sbom somewhere
# from sbom_search import search_sbom # If you use search_sbom

# ======================
#  CONFIGURATION
# ======================

# Remote API endpoint for generating the SBOM
REMOTE_SBOM_API = "https://sbom.onrender.com/generate-sbom/"

# Path to your signtool.exe if available (Windows)
SIGNSTOOL_PATH = r"C:\Users\cyria\signtool.exe"

# Streamlit Page Config
st.set_page_config(page_title="SBOM Analyzer", page_icon="🔍", layout="wide")

# UI CSS Enhancements
st.markdown("""
    <style>
    .stApp { background: linear-gradient(135deg, #1f4037, #99f2c8); color: white; }
    [data-testid="stSidebar"] { background: #1f2833; color: white; }
    .stMarkdown h1, .stMarkdown h2, .stMarkdown h3 { color: #ffcc00; }
    div.stButton > button { background-color: #008CBA; color: white; border-radius: 8px; }
    div.stButton > button:hover { background-color: #005f73; }
    </style>
""", unsafe_allow_html=True)

# ======================
#  TITLE
# ======================

st.title("🔍 SBOM Analyzer - Generator, Parser & Comparator")

# ======================
#  SIDEBAR
# ======================

st.sidebar.header("📂 Upload Software Application or SBOM File")
file1 = st.sidebar.file_uploader("🆕 Upload First File", type=["exe", "json", "spdx", "csv", "xml"])
file2 = st.sidebar.file_uploader("📑 Upload Second File (Optional for Comparison)", type=["exe", "json", "spdx", "csv", "xml"])

generate_button = st.sidebar.button("🔄 Generate SBOM")
compare_button = st.sidebar.button("🔍 Compare SBOMs")
# If you want to enable these later, uncomment:
# search_button = st.sidebar.button("🔎 Search SBOM Components")
# parse_button = st.sidebar.button("📜 Parse SBOM Data")

# ======================
#  HELPER FUNCTIONS
# ======================

def save_uploaded_file(uploaded_file, folder="uploaded_apps"):
    """
    Save the uploaded file to a local folder, ensuring correct permissions.
    Returns the full path to the saved file or None on error.
    """
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

def check_digital_signature(file_path):
    """
    Checks if an EXE is signed using signtool.exe (if present).
    Returns a short descriptor or warning.
    """
    if not os.path.exists(SIGNSTOOL_PATH):
        return "⚠️ Signature Check Tool Not Found"

    try:
        result = subprocess.run(
            [SIGNSTOOL_PATH, "verify", "/pa", file_path],
            capture_output=True, text=True, check=False
        )

        if "Successfully verified" in result.stdout:
            return "✅ Signed"
        elif ("No signature" in result.stdout) or ("is not signed" in result.stdout):
            return "❌ Not Signed"
        else:
            return f"⚠️ Unknown Signature Status: {result.stdout.strip()}"
    except Exception as e:
        return f"❌ Error Checking Signature: {e}"

def extract_file_metadata(file_path):
    """
    Extracts EXE-specific metadata (compiler, platform, vendor, signature).
    If it's not an EXE, returns defaults.
    """
    compiler = "Unknown"
    arch = platform.architecture()[0]
    vendor = "Unknown"
    digital_signature = "Not Available"

    # If it's an EXE, try parsing with pefile
    if file_path.lower().endswith(".exe"):
        try:
            pe = pefile.PE(file_path)

            # Compiler version
            if hasattr(pe, "OPTIONAL_HEADER"):
                major = pe.OPTIONAL_HEADER.MajorLinkerVersion
                minor = pe.OPTIONAL_HEADER.MinorLinkerVersion
                compiler = f"Linker {major}.{minor}"

            # Vendor from FileInfo
            if hasattr(pe, "FileInfo"):
                for file_info in pe.FileInfo:
                    if hasattr(file_info, "StringTable"):
                        for entry in file_info.StringTable:
                            for key, value in entry.entries.items():
                                try:
                                    key_decoded = key.decode(errors="ignore").strip()
                                    val_decoded = value.decode(errors="ignore").strip()
                                    if key_decoded == "CompanyName" and val_decoded:
                                        vendor = val_decoded
                                except AttributeError:
                                    continue

            # Digital signature
            digital_signature = check_digital_signature(file_path)

        except Exception as e:
            compiler = "Error Extracting Compiler"
            vendor = f"Error Extracting Vendor: {e}"
            digital_signature = "Error Extracting Digital Signature"

    return {
        "Compiler": compiler,
        "Platform": arch,
        "Vendor": vendor,
        "Digital Signature": digital_signature
    }

def download_sbom_report(sbom_data, file_name="sbom_report.json"):
    """
    Provide a Streamlit download button for the SBOM JSON.
    """
    sbom_json = json.dumps(sbom_data, indent=4)
    st.download_button(
        label="📥 Download SBOM Report",
        data=sbom_json,
        file_name=file_name,
        mime="application/json"
    )

def display_sbom_data(sbom_data, file_path):
    """
    Display SBOM metadata & components in the Streamlit app.
    """
    if not sbom_data:
        st.warning("⚠️ No SBOM data available.")
        return

    metadata = sbom_data.get("metadata", {})
    tools = metadata.get("tools", [])

    # Extract tool info
    tool_used = "Unknown"
    tool_version = "Unknown"
    if isinstance(tools, list) and tools:
        # Just use the first tool in the list
        first_tool = tools[0]
        tool_used = first_tool.get("name", "Unknown")
        tool_version = first_tool.get("version", "Unknown")

    # If still unknown, fallback to Syft or use the 'specVersion'
    if tool_used == "Unknown":
        tool_used = "Syft"
        tool_version = sbom_data.get("specVersion", "Unknown")

    # Local file metadata (EXE)
    file_meta = extract_file_metadata(file_path)

    # Vendor priority: SBOM metadata -> EXE info
    vendor = file_meta["Vendor"]
    if vendor == "Unknown":
        vendor = metadata.get("supplier", {}).get("name", "Unknown")

    # Software name from SBOM, fallback "Unknown"
    software_name = metadata.get("component", {}).get("name", "Unknown")

    # Compile a summary
    sbom_summary = {
        "Software Name": software_name,
        "Format": sbom_data.get("bomFormat", "Unknown"),
        "Version": sbom_data.get("specVersion", "Unknown"),
        "Generated On": metadata.get("timestamp", "Unknown"),
        "Tool Used": tool_used,
        "Tool Version": tool_version,
        "Vendor": vendor,
        "Compiler": file_meta["Compiler"],
        "Platform": file_meta["Platform"],
        "Digital Signature": file_meta["Digital Signature"]
    }

    st.subheader("📄 SBOM Metadata")
    st.table(pd.DataFrame(sbom_summary.items(), columns=["Attribute", "Value"]))

    # Download the SBOM as JSON
    download_sbom_report(sbom_data, file_name=f"{software_name}_SBOM.json")

    # Display components, if any
    if "components" in sbom_data and isinstance(sbom_data["components"], list):
        st.subheader("🛠️ SBOM Components")
        st.dataframe(pd.DataFrame(sbom_data["components"]))
    else:
        st.warning("⚠️ No components found.")

# ======================
#  REMOTE API SBOM GENERATION
# ======================

def generate_sbom(file_path, output_folder="generated_sboms"):
    """
    Calls the remote SBOM generation API at REMOTE_SBOM_API.
    Writes the returned JSON to a local file, and returns the path to that file.
    """
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    if not os.path.isfile(file_path):
        st.error(f"File not found: {file_path}")
        return None

    with open(file_path, "rb") as f:
        files = {"file": f}
        try:
            response = requests.post(REMOTE_SBOM_API, files=files)
        except Exception as exc:
            st.error(f"❌ Error reaching SBOM generation API: {exc}")
            return None

    if response.status_code == 200:
        # Parse JSON
        sbom_data = response.json()
        # Write to local file
        base_name = os.path.basename(file_path) + "_sbom.json"
        sbom_path = os.path.join(output_folder, base_name)
        with open(sbom_path, "w", encoding="utf-8") as out_f:
            json.dump(sbom_data, out_f, indent=4)
        return sbom_path
    else:
        st.error(f"❌ Failed to generate SBOM (Status Code: {response.status_code})")
        return None

# ======================
#  MAIN LOGIC
# ======================

# --- (1) Generate SBOM ---
if generate_button and file1:
    file1_path = save_uploaded_file(file1)
    if file1_path:
        sbom_path = generate_sbom(file1_path)
        if sbom_path and os.path.isfile(sbom_path):
            # Now read & display
            with open(sbom_path, "r", encoding="utf-8") as f:
                sbom_data = json.load(f)
            display_sbom_data(sbom_data, file1_path)
        else:
            st.error("❌ SBOM generation returned no file.")

# --- (2) Compare SBOMs ---
if compare_button and file1 and file2:
    st.subheader("📊 SBOM Comparison Results")

    file1_path = save_uploaded_file(file1)
    file2_path = save_uploaded_file(file2)
    if not file1_path or not file2_path:
        st.error("❌ One or both files could not be saved.")
    else:
        # If not JSON, generate SBOM first
        if not file1_path.endswith(".json"):
            file1_path = generate_sbom(file1_path)  # returns JSON path
        if not file2_path.endswith(".json"):
            file2_path = generate_sbom(file2_path)  # returns JSON path

        if file1_path and file2_path and os.path.isfile(file1_path) and os.path.isfile(file2_path):
            # Compare
            added, removed, error = compare_sboms(file1_path, file2_path)

            if error:
                st.error(f"❌ {error}")
            else:
                col1, col2 = st.columns(2)

                with col1:
                    st.write("### ✅ Added Components")
                    if added:
                        st.dataframe(pd.DataFrame(list(added), columns=["Added Components"]))
                    else:
                        st.info("No new components added.")

                with col2:
                    st.write("### ❌ Removed Components")
                    if removed:
                        st.dataframe(pd.DataFrame(list(removed), columns=["Removed Components"]))
                    else:
                        st.info("No components removed.")
        else:
            st.error("❌ Could not generate SBOM for one or both files.")

# --- (3) (Optional) Search SBOM, Parse SBOM, etc. ---
# if search_button and file1:
#     st.write("Search logic goes here...")

# if parse_button and file1:
#     st.write("Parsing logic goes here...")
