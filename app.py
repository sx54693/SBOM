import streamlit as st
import os
import json
import pandas as pd
import platform
import pefile
import subprocess
import requests

# Local modules (assuming they exist)
from sbom_compare import compare_sboms
from sbom_parser import parse_sbom
from sbom_search import search_sbom

API_URL = "https://sbom.onrender.com/generate-sbom/"
signtool_path = "C:\\Users\\cyria\\signtool.exe"

st.set_page_config(page_title="SBOM Analyzer", page_icon="🔍", layout="wide")

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

st.title("🔍 SBOM Analyzer - Generator, Parser, Comparator & Search")

# ======================
#  SIDEBAR
# ======================
st.sidebar.header("📂 Upload Software Application or SBOM File")
file1 = st.sidebar.file_uploader("🆕 Upload First File", type=["exe", "json", "spdx", "csv", "xml"])
file2 = st.sidebar.file_uploader("📑 Upload Second File (Optional for Comparison)", type=["exe", "json", "spdx", "csv", "xml"])

generate_button = st.sidebar.button("🔄 Generate SBOM")
compare_button = st.sidebar.button("🔍 Compare SBOMs")
search_button = st.sidebar.button("🔎 Search SBOM Components")
parse_button = st.sidebar.button("📜 Parse SBOM Data")


def save_uploaded_file(uploaded_file, folder="uploaded_apps"):
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


def extract_file_metadata(file_path):
    compiler = "Unknown"
    arch = platform.architecture()[0]
    vendor = "Unknown"
    digital_signature = "Not Available"

    if file_path.lower().endswith(".exe"):
        import pefile
        try:
            pe = pefile.PE(file_path)
            if hasattr(pe, "OPTIONAL_HEADER"):
                major = pe.OPTIONAL_HEADER.MajorLinkerVersion
                minor = pe.OPTIONAL_HEADER.MinorLinkerVersion
                compiler = f"Linker {major}.{minor}"
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


def download_sbom_report(sbom_data, file_name="sbom_report.json"):
    sbom_json = json.dumps(sbom_data, indent=4)
    st.download_button(
        label="📥 Download SBOM Report",
        data=sbom_json,
        file_name=file_name,
        mime="application/json",
        key=f"download-{file_name}"
    )


def display_sbom_data(sbom_data, file_path):
    if not sbom_data:
        st.warning("⚠️ No SBOM data available.")
        return
    metadata = sbom_data.get("metadata", {})
    tools = metadata.get("tools", [])
    tool_used = "Syft"
    tool_version = sbom_data.get("specVersion", "Unknown")
    if tools and isinstance(tools, list):
        first_tool = tools[0]
        tool_used = first_tool.get("name", tool_used)
        tool_version = first_tool.get("version", tool_version)
    software_name = metadata.get("component", {}).get("name", None)
    if not software_name:
        software_name = os.path.basename(file_path)
    vendor = metadata.get("supplier", {}).get("name", "Unknown")
    file_metadata = extract_file_metadata(file_path)
    if vendor == "Unknown":
        vendor = file_metadata["Vendor"]
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
    st.subheader("📄 SBOM Metadata")
    st.table(pd.DataFrame(sbom_summary.items(), columns=["Attribute", "Value"]))
    download_sbom_report(sbom_data, file_name=f"{software_name}_SBOM.json")
    components = sbom_data.get("components", [])
    if components and isinstance(components, list):
        st.subheader("🛠️ SBOM Components")
        st.dataframe(pd.DataFrame(components))
    else:
        st.warning("⚠️ No components found.")


def generate_sbom(file_path):
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
        return response.json()
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
    st.subheader("📊 SBOM Comparison Results")

    # 1) Save both files
    file1_path = save_uploaded_file(file1)
    file2_path = save_uploaded_file(file2)

    if not file1_path or not file2_path:
        st.error("Could not save one of the uploaded files.")
        st.stop()

    # 2) If the file is an EXE, generate an SBOM via Render API
    #    Else, parse it as an existing SBOM
    def get_sbom_data(local_path):
        if local_path.lower().endswith(".exe"):
            return generate_sbom(local_path)
        else:
            # parse_sbom is presumably your local function that loads JSON, SPDX, etc.
            return parse_sbom(local_path)

    sbom_data_1 = get_sbom_data(file1_path)
    sbom_data_2 = get_sbom_data(file2_path)

    if not sbom_data_1 or not sbom_data_2:
        st.error("One or both SBOMs could not be generated or parsed.")
        st.stop()

    # 3) Compare them using compare_sboms (which expects two SBOM dicts)
    # --- 2) Compare SBOMs ---
if compare_button and file1 and file2:
    st.subheader("📊 SBOM Comparison Results")

    # 1) Save both files
    file1_path = save_uploaded_file(file1)
    file2_path = save_uploaded_file(file2)

    if not file1_path or not file2_path:
        st.error("❌ Could not save one (or both) uploaded files.")
        st.stop()

    # 2) If the file is an EXE, generate an SBOM via the API
    #    Otherwise, parse it as an existing SBOM
    def get_sbom_data(local_path):
        if local_path.lower().endswith(".exe"):
            return generate_sbom(local_path)  # returns dict
        else:
            return parse_sbom(local_path)     # also returns dict

    sbom_data_1 = get_sbom_data(file1_path)
    sbom_data_2 = get_sbom_data(file2_path)

    if not sbom_data_1 or not sbom_data_2:
        st.error("❌ Could not generate/parse one (or both) SBOMs.")
        st.stop()

    # 3) Compare them using compare_sboms (which returns 4 items now)
    # --- 2) Compare SBOMs ---
if compare_button and file1 and file2:
    st.subheader("📊 SBOM Comparison Results")

    # 1) Save both files
    file1_path = save_uploaded_file(file1)
    file2_path = save_uploaded_file(file2)

    if not file1_path or not file2_path:
        st.error("❌ Could not save one (or both) uploaded files.")
        st.stop()

    # 2) If the file is an EXE, generate an SBOM via the API
    #    Otherwise, parse it as an existing SBOM
    def get_sbom_data(local_path):
        if local_path.lower().endswith(".exe"):
            return generate_sbom(local_path)  # returns dict
        else:
            return parse_sbom(local_path)     # also returns dict

    sbom_data_1 = get_sbom_data(file1_path)
    sbom_data_2 = get_sbom_data(file2_path)

    if not sbom_data_1 or not sbom_data_2:
        st.error("❌ Could not generate/parse one (or both) SBOMs.")
        st.stop()

    # 3) Compare them using compare_sboms (which returns 4 items now)
    added, removed, changed, error = compare_sboms(sbom_data_1, sbom_data_2)
    if error:
        st.error(f"Comparison error: {error}")
    else:
        # 3a) ADDED
        st.write("### ✅ Added Components")
        if added:
            # If 'added' is a list of dicts or strings, adapt as needed
            st.dataframe(pd.DataFrame(added))
        else:
            st.info("No newly added components.")

        # 3b) REMOVED
        st.write("### ❌ Removed Components")
        if removed:
            st.dataframe(pd.DataFrame(removed))
        else:
            st.info("No components removed.")

        # 3c) CHANGED
        st.write("### 🔄 Changed Components")
        if changed:
            # If 'changed' is a list of tuples like: (name, old_info, new_info)
            # we can convert it to a list of dicts for easier display
            changed_rows = []
            for comp_name, old_data, new_data in changed:
                changed_rows.append({
                    "Component Name": comp_name,
                    "Old Version": old_data.get("version", "N/A"),
                    "New Version": new_data.get("version", "N/A"),
                    "Old Supplier": old_data.get("supplier", ""),
                    "New Supplier": new_data.get("supplier", "")
                })
            st.dataframe(pd.DataFrame(changed_rows))
        else:
            st.info("No components changed.")


# --- 3) Search SBOM Components ---
if search_button and file1:
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

