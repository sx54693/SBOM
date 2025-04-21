import os
import json
import hashlib
import platform
import subprocess
import pefile
import re
import streamlit as st
import pandas as pd
import sys
if sys.platform.startswith("win"):
    import os
    os.environ["PYTHONIOENCODING"] = "utf-8"

from sbom_compare import compare_sboms
from sbom_generator import generate_sbom
from sbom_parser import parse_sbom
from sbom_search import load_sbom, fuzzy_search_components
from features import display_advanced_features


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# ✅ Save uploaded file safely
def save_uploaded_file(uploaded_file, folder="uploaded_apps"):
    import re
    def secure_filename(filename):
        filename = os.path.basename(filename)
        filename = re.sub(r'[^\w\-.]', '_', filename)
        return filename.strip()

    if not uploaded_file:
        return None
    if not os.path.exists(folder):
        os.makedirs(folder)

    try:
        safe_name = secure_filename(uploaded_file.name)
        file_path = os.path.join(folder, safe_name)
        with open(file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        os.chmod(file_path, 0o777)
        return file_path
    except Exception as e:
        st.error(f"❌ Failed to save file: {e}")
        return None

st.set_page_config(page_title="SBOM Analyzer", page_icon="🔍", layout="wide")

st.markdown("""
    <style>
    .stApp { background: linear-gradient(135deg, #1f4037, #99f2c8); color: white; }
    [data-testid="stSidebar"] { background: #1f2833; color: white; }
    .stMarkdown h1, .stMarkdown h2, .stMarkdown h3 { color: #ffcc00; }
    div.stButton > button { background-color: #008CBA; color: white; border-radius: 8px; }
    div.stButton > button:hover { background-color: #005f73; }
    </style>
""", unsafe_allow_html=True)

st.title("🔍 SBOM Analyzer - Generator, Parser & Comparator")

st.sidebar.header("📂 Upload Software Application or SBOM File")
file1 = st.sidebar.file_uploader("🆕 Upload First File", type=["exe", "apk", "json", "spdx", "csv", "xml"])
file2 = st.sidebar.file_uploader("📁 Upload Second File (Optional for Comparison)", type=["exe", "apk", "json", "spdx", "csv", "xml"])

generate_button = st.sidebar.button("🔄 Generate SBOM")
compare_button = st.sidebar.button("🔍 Compare SBOMs")
file1_path = None
file1_sbom = None
apk_details = {}
if file1:
    file1_path = save_uploaded_file(file1)
    if file1_path:
        if file1_path.endswith(".json"):
            with open(file1_path, "r", encoding="utf-8") as f:
                file1_sbom = json.load(f)
        else:
            file1_sbom, *_rest = generate_sbom(file1_path)
            apk_details = _rest[-1] if len(_rest) >= 1 else {}
display_advanced_features()
# ✅ Run fuzzy search only if SBOM is loaded
if "file1_sbom" in locals() and file1_sbom:
    st.subheader("🔍 Fuzzy Search")
    search_query = st.text_input("Enter component name to search", key="fuzzy_key")

    if search_query:
        results = fuzzy_search_components(file1_sbom, apk_details, search_query)
        if results:
            st.subheader("🔍 Fuzzy Search Results")
            st.dataframe(pd.DataFrame(results))
        else:
            st.warning("No matching components found.")
else:
    st.info("📥 Please generate or upload an SBOM first.")


def secure_filename(filename):
    filename = os.path.basename(filename)
    filename = re.sub(r'[^\w\-.]', '_', filename)
    return filename.strip()


def extract_with_7zip(file_path):
    try:
        result = subprocess.run(["7z", "l", file_path], capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return f"❌ 7-Zip Error: {str(e)}"

def extract_exe_libraries(file_path):
    try:
        pe = pefile.PE(file_path)
        imports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        imports.append(imp.name.decode('utf-8'))
        return imports
    except Exception as e:
        return [f"❌ Error extracting DLLs: {str(e)}"]

def parse_apk_with_apktool(file_path):
    try:
        out_dir = os.path.join("decoded_apks", os.path.basename(file_path).replace(".apk", ""))
        os.makedirs("decoded_apks", exist_ok=True)

        result = subprocess.run(
            ["apktool", "d", "-f", file_path, "-o", out_dir],
            capture_output=True, text=True, encoding="utf-8", errors="replace"
        )
        log_output = result.stdout + "\n" + result.stderr

        packages = []
        libraries = set()
        known_libs = [
            "com.google", "com.facebook", "com.bumptech.glide", "com.android",
            "org.apache", "org.greenrobot", "com.squareup", "io.reactivex",
            "androidx", "kotlin", "dagger", "javax", "okhttp3"
        ]

        smali_dir = os.path.join(out_dir, "smali")
        if os.path.exists(smali_dir):
            for root, _, files in os.walk(smali_dir):
                for file in files:
                    if file.endswith(".smali"):
                        package_path = os.path.relpath(root, smali_dir).replace(os.sep, ".")
                        if package_path not in packages:
                            packages.append(package_path)
                        for lib in known_libs:
                            if package_path.startswith(lib):
                                libraries.add(lib)

        lib_dir = os.path.join(out_dir, "lib")
        native_libs = []
        if os.path.exists(lib_dir):
            for root, _, files in os.walk(lib_dir):
                for file in files:
                    if file.endswith(".so"):
                        native_libs.append(file)

        libraries.update(native_libs)

        try:
            aapt_out = subprocess.check_output(
                ["aapt", "dump", "badging", file_path],
                encoding="utf-8", errors="replace"
            )
            package_line = next((line for line in aapt_out.splitlines() if line.startswith("package:")), "")
        except Exception as e:
            package_line = f"⚠️ AAPT Error: {str(e)}"

        permissions = []
        manifest_path = os.path.join(out_dir, "AndroidManifest.xml")
        if os.path.exists(manifest_path):
            with open(manifest_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if "uses-permission" in line:
                        permissions.append(line.strip())

        apk_details = {
            "Package Info": package_line,
            "Permissions": permissions,
            "Libraries": sorted(libraries)
        }

        return log_output, packages, apk_details

    except Exception as e:
        return f"❌ APKTool Error: {str(e)}", [], {}


def display_sbom_data(sbom_data, file_path, apk_details=None):
    metadata = sbom_data.get("metadata", {})
    tool_used = "Syft"
    tool_version = sbom_data.get("specVersion", "Unknown")
    vendor = metadata.get("supplier", {}).get("name", "Unknown")
    software_name = metadata.get("component", {}).get("name", os.path.basename(file_path))
    platform_info = platform.architecture()[0]

    sbom_summary = {
        "Software Name": software_name,
        "Format": sbom_data.get("bomFormat", "Unknown"),
        "Version": sbom_data.get("specVersion", "Unknown"),
        "Generated On": metadata.get("timestamp", "Unknown"),
        "Tool Used": tool_used,
        "Tool Version": tool_version,
        "Vendor": vendor,
        "Binary Type": sbom_data.get("Binary Type", "Unknown"),
        "Platform": platform_info
    }

    st.subheader("📄 SBOM Metadata")
    st.table(pd.DataFrame(sbom_summary.items(), columns=["Attribute", "Value"]))

    if "components" in sbom_data and isinstance(sbom_data["components"], list):
        st.subheader("🛠️ SBOM Components")
        components_df = pd.DataFrame(sbom_data["components"])
        st.dataframe(components_df)
    else:
        st.warning("⚠️ No components found.")

    with st.expander("📦 7-Zip Archive Contents"):
        st.code(extract_with_7zip(file_path))

    if file_path.endswith(".exe"):
        dlls = extract_exe_libraries(file_path)
        st.subheader("App Details from Executable")

        if dlls:
            st.write("**Libraries (from DLL Imports):**")
            st.code("\n".join(dlls))
        else:
            st.info("No DLL imports found or could not extract.")

        archive_output = extract_with_7zip(file_path)
        archive_lines = archive_output.splitlines()
        archive_components = [line.strip().split()[-1] for line in archive_lines if any(ext in line.lower() for ext in [".dll", ".exe"])]

        if archive_components:
            st.write("**Inferred Libraries from Archive:**")
            st.code("\n".join(sorted(set(archive_components))))
        else:
            st.info("No inferred libraries found in archive.")

    if file_path.endswith(".apk"):
        log_output, packages, apk_details_partial = parse_apk_with_apktool(file_path)
        apk_details = apk_details or {}
        apk_details.update(apk_details_partial)

        with st.expander("📦 APKTool Log Output"):
            st.code(log_output)
        with st.expander("📦 Smali Packages (.apk)"):
            st.write(packages)

        if apk_details:
            st.subheader("App Details from Manifest")
            st.write("**Package Info:**", apk_details.get("Package Info", "N/A"))
            st.write("**Permissions:**")
            st.code("\n".join(apk_details.get("Permissions", [])))
            st.write("**Libraries:**")
            st.code("\n".join(apk_details.get("Libraries", [])))
      

if generate_button and file1:
    file1_path = save_uploaded_file(file1)
    sbom_data, _, _, _, _, apk_details = generate_sbom(file1_path)
    if sbom_data:
        file1_sbom = sbom_data  # ✅ Needed for fuzzy search
        display_sbom_data(sbom_data, file1_path, apk_details)

if compare_button and file1 and file2:
    file1_path = save_uploaded_file(file1)
    file2_path = save_uploaded_file(file2)

    # Process File 1
    if file1_path.endswith(".json"):
        with open(file1_path, "r", encoding="utf-8") as f:
            file1_sbom = json.load(f)
        apk_details_1 = {}
    else:
        file1_sbom, *_rest = generate_sbom(file1_path)
        apk_details_1 = _rest[-1] if len(_rest) >= 1 else {}

    # Process File 2
    if file2_path.endswith(".json"):
        with open(file2_path, "r", encoding="utf-8") as f:
            file2_sbom = json.load(f)
        apk_details_2 = {}
    else:
        file2_sbom, *_rest = generate_sbom(file2_path)
        apk_details_2 = _rest[-1] if len(_rest) >= 1 else {}

    if file1_sbom and file2_sbom:
        added, removed, error = compare_sboms(file1_sbom, file2_sbom)
        if error:
            st.error(f"❌ {error}")
        else:
            st.subheader("🔄 SBOM Comparison Results")

            # ✅ ADDED/REMOVED
            col1, col2 = st.columns(2)
            with col1:
                st.markdown("### ✅ Added Components")
                st.dataframe(pd.DataFrame(list(added), columns=["Added Components"])) if added else st.info("No new components added.")
            with col2:
                st.markdown("### ❌ Removed Components")
                st.dataframe(pd.DataFrame(list(removed), columns=["Removed Components"])) if removed else st.info("No components removed.")

            # 📄 METADATA COMPARISON
            st.subheader("📄 Metadata Comparison")

            def extract_metadata(sbom_data, file_path, apk_info=None):
                metadata = sbom_data.get("metadata", {})
                return {
                    "Software Name": metadata.get("component", {}).get("name", os.path.basename(file_path)),
                    "Format": sbom_data.get("bomFormat", "Unknown"),
                    "Version": sbom_data.get("specVersion", "Unknown"),
                    "Generated On": metadata.get("timestamp", "Unknown"),
                    "Vendor": metadata.get("supplier", {}).get("name", "Unknown"),
                    "Platform": platform.architecture()[0],
                    "Binary Type": sbom_data.get("Binary Type", "Unknown"),
                    "APK Package": apk_info.get("Package Info", "N/A") if apk_info else "N/A"
                }

            meta1 = extract_metadata(file1_sbom, file1_path, apk_details_1)
            meta2 = extract_metadata(file2_sbom, file2_path, apk_details_2)

            col1, col2 = st.columns(2)
            with col1:
                st.markdown("**App 1**")
                st.table(pd.DataFrame(meta1.items(), columns=["Attribute", "Value"]))
            with col2:
                st.markdown("**App 2**")
                st.table(pd.DataFrame(meta2.items(), columns=["Attribute", "Value"]))

            # 🔐 PERMISSIONS COMPARISON
            st.subheader("🔐 Permissions Comparison")
            col1, col2 = st.columns(2)
            with col1:
                st.markdown("**App 1 Permissions**")
                st.code("\n".join(apk_details_1.get("Permissions", [])) if apk_details_1 else "N/A")
            with col2:
                st.markdown("**App 2 Permissions**")
                st.code("\n".join(apk_details_2.get("Permissions", [])) if apk_details_2 else "N/A")

           # 📚 LIBRARIES COMPARISON
            st.subheader("📚 Library Comparison")
            col1, col2 = st.columns(2)

            lib1 = apk_details_1.get("Libraries", []) if apk_details_1 else []
            lib2 = apk_details_2.get("Libraries", []) if apk_details_2 else []

            with col1:
                st.markdown("**App 1 Libraries**")
                st.code("\n".join(lib1) if lib1 else "N/A")

            with col2:
                st.markdown("**App 2 Libraries**")
                st.code("\n".join(lib2) if lib2 else "N/A")
                from sbom_search import load_sbom, fuzzy_search_components
