import streamlit as st
import os
import json
import pandas as pd
import platform
import pefile
import subprocess
import requests

# If you have these local modules, keep these imports:
from sbom_compare import compare_sboms
from sbom_parser import parse_sbom
from sbom_search import search_sbom

# ========== CONFIGURATIONS ==========

# Render API endpoint for SBOM generation
API_URL = "https://sbom.onrender.com/generate-sbom/"

# If you do have signtool.exe locally on Windows, update this path accordingly:
signtool_path = "C:\\Users\\cyria\\signtool.exe"

# Page Config (Streamlit)
st.set_page_config(page_title="SBOM Analyzer", page_icon="🔍", layout="wide")

# UI Custom CSS
st.markdown(
    """
    <style>
    .stApp { background: linear-gradient(135deg, #1f4037, #99f2c8); color: white; }
    [data-testid="stSidebar"] { background: #1f2833; color: white; }
    .stMarkdown h1, .stMarkdown h2, .stMarkdown h3 { color: #ffcc00; }
    div.stButton > button {
        background-color: #008CBA; color: white; border-radius: 8px;
    }
    div.stButton > button:hover { background-color: #005f73; }
    </style>
    """,
    unsafe_allow_html=True
)

# ========== TITLE ==========

st.title("🔍 SBOM Analyzer - Generator, Parser, Comparator & Search")

# ========== SIDEBAR FILE UPLOAD & BUTTONS ==========

st.sidebar.header("📂 Upload Software Application or SBOM File")
file1 = st.sidebar.file_uploader("🆕 Upload First File", type=["exe", "json", "spdx", "csv", "xml"])
file2 = st.sidebar.file_uploader("📑 Upload Second File (Optional for Comparison)", type=["exe", "json", "spdx", "csv", "xml"])

generate_button = st.sidebar.button("🔄 Generate SBOM")
compare_button = st.sidebar.button("🔍 Compare SBOMs")
search_button = st.sidebar.button("🔎 Search SBOM Components")
parse_button = st.sidebar.button("📜 Parse SBOM Data")


# ========== FUNCTION: SAVE UPLOADED FILE ==========

def save_uploaded_file(uploaded_file, folder="uploaded_apps"):
    """
    Saves the uploaded file to a local 'uploaded_apps' folder (or custom folder),
    ensuring 777 permissions on Unix-like systems.
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


# ========== FUNCTION: CHECK DIGITAL SIGNATURE ==========

def check_digital_signature(file_path):
    """
    Attempts to verify a Windows EXE's digital signature using signtool.exe.
    Returns a short descriptor of the signature status, or a warning if unavailable.
    """
    # If the signtool path doesn't exist (e.g. on cloud or non-Windows),
    # skip the signature check:
    if not os.path.exists(signtool_path):
        return "⚠️ Signature Check Not Available"

    try:
        result = subprocess.run(
            [signtool_path, "verify", "/pa", file_path],
            capture_output=True, text=True, check=False
        )

        if "Successfully verified" in result.stdout:
            return "✅ Signed"
        elif ("No signature" in result.stdout) or ("is not signed" in result.stdout):
            return "❌ Not Signed"
        else:
            return f"⚠️ Unknown Signature Status: {result.stdout.strip()}"

    except Exception as e:
        return f"❌ Error Checking Signature: {str(e)}"


# ========== FUNCTION: EXTRACT FILE METADATA (EXE) ==========

def extract_file_metadata(file_path):
    """
    Safely extracts EXE-specific metadata: compiler, platform, vendor, and digital signature.
    Returns defaults for non-EXE files or on errors.
    """
    compiler = "Unknown"
    arch = platform.architecture()[0]
    vendor = "Unknown"
    digital_signature = "Not Available"

    # Only attempt if it's an EXE on Windows
    if file_path.lower().endswith(".exe"):
        try:
            pe = pefile.PE(file_path)

            # Extract Compiler Version (from PE OPTIONAL_HEADER)
            if hasattr(pe, "OPTIONAL_HEADER"):
                major = pe.OPTIONAL_HEADER.MajorLinkerVersion
                minor = pe.OPTIONAL_HEADER.MinorLinkerVersion
                compiler = f"Linker {major}.{minor}"

            # Extract Vendor (CompanyName) if present
            if hasattr(pe, "FileInfo"):
                for file_info in pe.FileInfo:
                    if hasattr(file_info, "StringTable"):
                        for entry in file_info.StringTable:
                            for key, value in entry.entries.items():
                                try:
                                    key_decoded = key.decode(errors="ignore").strip()
                                    value_decoded = value.decode(errors="ignore").strip()
                                    if key_decoded == "CompanyName" and value_decoded:
                                        vendor = value_decoded
                                except AttributeError:
                                    continue

            # Digital Signature
            digital_signature = check_digital_signature(file_path)

        except Exception as e:
            compiler = "Error Extracting Compiler"
            vendor = f"Error Extracting Vendor: {str(e)}"
            digital_signature = "Error Extracting Digital Signature"

    return {
        "Compiler": compiler,
        "Platform": arch,
        "Vendor": vendor,
        "Digital Signature": digital_signature
    }


# ========== FUNCTION: DOWNLOAD SBOM REPORT ==========

def download_sbom_report(sbom_data, file_name="sbom_report.json"):
    """
    Presents a download button for the SBOM JSON to the user.
    """
    sbom_json = json.dumps(sbom_data, indent=4)
    st.download_button(
        label="📥 Download SBOM Report",
        data=sbom_json,
        file_name=file_name,
        mime="application/json",
        key=f"download-{file_name}"  # Unique key to avoid repeated widget ID conflicts
    )


# ========== FUNCTION: DISPLAY SBOM DATA ==========

def display_sbom_data(sbom_data, file_path):
    """
    Takes the SBOM data (as a Python dict) and the file path for local metadata.
    Displays summary info, metadata, and components in the Streamlit UI.
    """
    if not sbom_data:
        st.warning("⚠️ No SBOM data available.")
        return

    # 1) Extract relevant SBOM metadata
    metadata = sbom_data.get("metadata", {})
    tools = metadata.get("tools", [])

    # Tool info (defaults to Syft + specVersion)
    tool_used = "Syft"
    tool_version = sbom_data.get("specVersion", "Unknown")
    if tools and isinstance(tools, list):
        first_tool = tools[0]
        # fallback if key not found
      if tool_used == "Unknown"
    tool_used = "Syft"
    tool_version = sbom_data.get("specVersion", "Unknown")

    # Software name
    software_name = metadata.get("component", {}).get("name", None)
    if not software_name:
        software_name = os.path.basename(file_path)  # fallback: the filename

    # Vendor (from SBOM metadata supplier, else fallback after local extraction)
    vendor = metadata.get("supplier", {}).get("name", "Unknown")

    # 2) Extract local EXE metadata (if applicable)
    file_metadata = extract_file_metadata(file_path)

    # If SBOM has no vendor, fallback to local vendor from EXE
    if vendor == "Unknown":
        vendor = file_metadata["Vendor"]

    # 3) Compose a summary dictionary
    sbom_summary = {
        "Software Name": software_name,
        "Format": sbom_data.get("bomFormat", "CycloneDX"),
        "Version": sbom_data.get("specVersion", "Unknown"),
        "Generated On": metadata.get("timestamp", "N/A"),
        "Tool Used": tool_used,
        "Tool Version": tool_version,
        "Vendor": vendor,
        "Compiler": file_metadata["Compiler"],
        "Platform": file_metadata["Platform"],
        "Digital Signature": file_metadata["Digital Signature"]
    }

    # 4) Display metadata as a table
    st.subheader("📄 SBOM Metadata")
    st.table(pd.DataFrame(sbom_summary.items(), columns=["Attribute", "Value"]))

    # 5) Download button for the SBOM data
    download_sbom_report(sbom_data, file_name=f"{software_name}_SBOM.json")

    # 6) If components exist, show them in a DataFrame
    components = sbom_data.get("components", [])
    if components and isinstance(components, list):
        st.subheader("🛠️ SBOM Components")
        st.dataframe(pd.DataFrame(components))
    else:
        st.warning("⚠️ No components found.")


# ========== FUNCTION: GENERATE SBOM (CALL RENDER API) ==========

def generate_sbom(file_path):
    """
    Calls your Render API endpoint to generate an SBOM from an uploaded file.
    Returns the SBOM as a Python dict, or None on error.
    """
    if not os.path.isfile(file_path):
        st.error(f"File not found: {file_path}")
        return None

    with open(file_path, "rb") as f:
        files = {"file": f}
        try:
            response = requests.post(API_URL, files=files)
        except Exception as exc:
            st.error(f"❌ Error reaching SBOM generation API: {exc}")
            return None

    if response.status_code == 200:
        return response.json()  # parsed JSON
    else:
        st.error(f"❌ Failed to generate SBOM. API responded with {response.status_code}.")
        return None


# ========== MAIN LOGIC: BUTTON HANDLERS ==========

# --- 1) Generate SBOM ---
if generate_button and file1:
    file1_path = save_uploaded_file(file1)
    if file1_path:
        sbom_data = generate_sbom(file1_path)
        if sbom_data:
            display_sbom_data(sbom_data, file1_path)
        else:
            st.error("❌ SBOM generation returned no data.")

# --- 2) Compare SBOMs ---
if compare_button and file1 and file2:
    # Example usage - you’d adjust to your local logic
    # 1) Save both files
    file1_path = save_uploaded_file(file1)
    file2_path = save_uploaded_file(file2)

    # 2) If they are both SBOMs, parse them and compare
    if file1_path and file2_path:
        sbom_data_1 = parse_sbom(file1_path)
        sbom_data_2 = parse_sbom(file2_path)
        comparison_result = compare_sboms(sbom_data_1, sbom_data_2)
        st.write("Comparison Results:", comparison_result)

# --- 3) Search SBOM Components ---
if search_button and file1:
    # Save file & parse SBOM
    file1_path = save_uploaded_file(file1)
    if file1_path:
        sbom_data = parse_sbom(file1_path)  # must be implemented in sbom_parser.py
        if sbom_data:
            search_term = st.text_input("Enter component name or keyword to search")
            if search_term:
                results = search_sbom(sbom_data, search_term)
                st.write("Search Results:", results)
        else:
            st.error("❌ Parsing SBOM failed.")

# --- 4) Parse SBOM Data ---
if parse_button and file1:
    file1_path = save_uploaded_file(file1)
    if file1_path:
        sbom_data = parse_sbom(file1_path)
        if sbom_data:
            display_sbom_data(sbom_data, file1_path)
        else:
            st.error("❌ Parsing SBOM returned no data.")
