import os
import json
import platform
import subprocess
import pefile
import re
import streamlit as st
import pandas as pd
import sys

if sys.platform.startswith("win"):
    os.environ["PYTHONIOENCODING"] = "utf-8"

from sbom_compare import compare_sboms
from sbom_generator import generate_sbom
from sbom_parser import parse_sbom
from sbom_search import load_sbom, fuzzy_search_components
from features import display_advanced_features
from sbom_security import scan_vulnerabilities_and_licenses
from sbom_report import download_sbom_report  
from sbom_parser import parse_sbom



BASE_DIR = os.path.dirname(os.path.abspath(__file__))
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

    # ⚡ FIX: Define archive_output once
    archive_output = extract_with_7zip(file_path)

    st.subheader("📄 SBOM Metadata")
    st.table(pd.DataFrame(sbom_summary.items(), columns=["Attribute", "Value"]))

    if "components" in sbom_data and isinstance(sbom_data["components"], list):
        st.subheader("🛠️ SBOM Components")
        components_df = pd.DataFrame(sbom_data["components"])
        st.dataframe(components_df)
    else:
        st.warning("⚠️ No components found.")

    with st.expander("📦 7-Zip Archive Contents"):
        st.code(archive_output)

    if file_path.endswith(".exe"):
        st.subheader("🖥️ Executable File Deep Analysis")

        with st.expander("🔗 DLL Imports (Extracted Libraries)"):
            dlls = extract_exe_libraries(file_path)
            if dlls:
                st.code("\n".join(dlls))
            else:
                st.info("No DLL imports found or extraction failed.")

        inferred_components = [line.strip().split()[-1] for line in archive_output.splitlines() if any(ext in line.lower() for ext in [".dll", ".exe"])]

        with st.expander("📝 Inferred Libraries from Archive Structure"):
            if inferred_components:
                st.code("\n".join(sorted(set(inferred_components))))
            else:
                st.info("No inferred libraries detected.")

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
                # 🛡️ VULNERABILITY & LICENSE CHECKS (For App 1)
            st.subheader("🛡️ Vulnerability Scan Results")
            vulnerabilities, licenses = scan_vulnerabilities_and_licenses(apk_details)

            if vulnerabilities:
                for lib, vulns in vulnerabilities.items():
                    st.markdown(f"**{lib}**: {', '.join(vulns) if vulns else '✅ No known vulnerabilities'}")
            else:
                st.info("No libraries detected for vulnerability scanning.")

            st.subheader("📜 License Compliance Results")
            if licenses:
                for lib, license in licenses.items():
                    st.markdown(f"**{lib}**: `{license}`")
            else:
                st.info("No libraries detected for license analysis.")
            
    if generate_button:
        if not file1:
            st.error("❌ Please upload a file before generating SBOM.")
    else:
        file1_path = save_uploaded_file(file1)

        if not file1_path:
            st.error("❌ File upload failed. Cannot proceed.")
        else:
            if file1_path.endswith(".json"):
                with open(file1_path, "r", encoding="utf-8") as f:
                    sbom_data = json.load(f)
                apk_details = {}   # No APK details for JSON
                st.success("✅ SBOM Loaded from JSON!")
            else:
                sbom_data, _, _, _, _, apk_details = generate_sbom(file1_path)
                if sbom_data:
                    st.success("✅ SBOM Generated Successfully!")
                else:
                    st.error("❌ SBOM generation failed.")

            if sbom_data:
                display_sbom_data(sbom_data, file1_path, apk_details)



def save_uploaded_file(uploaded_file, folder="uploaded_apps"):
    if not uploaded_file:
        return None

    os.makedirs(folder, exist_ok=True)

    # Full sanitization: Remove problematic characters & spaces
    safe_name = re.sub(r'[<>:"/\\|?*]', '_', uploaded_file.name).strip()
    safe_name = safe_name.replace(' ', '_')  # Replace spaces for safety

    # Ensure filename is not empty after sanitization
    if not safe_name:
        st.error("❌ Invalid filename after sanitization.")
        return None

    file_path = os.path.join(folder, safe_name)

    try:
        with open(file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        return file_path
    except Exception as e:
        st.error(f"❌ Failed to save file: {e}")
        return None
    # Load or Generate SBOMs
def process_file(file_path):
    if not file_path:
        st.error("❌ Missing file path for SBOM processing.")
        return None, {}
    elif file_path.endswith(".json"):
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f), {}
    else:
        sbom_data, *_rest = generate_sbom(file_path)
        apk_info = _rest[-1] if len(_rest) >= 1 else {}
        return sbom_data, apk_info
    file1_sbom, apk_details_1 = process_file(file1_path)
    file2_sbom, apk_details_2 = process_file(file2_path)

    
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
parse_button = st.sidebar.button("📂 Parse Uploaded SBOM (JSON Only)")

file1_path = None
file1_sbom = None
apk_details = {}
sbom_data = None

# ▶️ Generate or Load SBOM
if generate_button and file1:
    file1_path = save_uploaded_file(file1)
    if file1_path:
        if file1_path.endswith(".json"):
            with open(file1_path, "r", encoding="utf-8") as f:
                sbom_data = json.load(f)
            st.success("✅ SBOM Loaded from JSON!")
            apk_details = {}  # No APK info from JSON
        else:
            sbom_data, *_rest = generate_sbom(file1_path)
            apk_details = _rest[-1] if len(_rest) >= 1 else {}
            if sbom_data:
                st.success("✅ SBOM Generated Successfully!")
            else:
                st.error("❌ SBOM generation failed.")
    else:
        st.error("❌ File upload failed.")

    # ✅ Display and Store SBOM if successful
    if sbom_data:
        file1_sbom = sbom_data
        display_sbom_data(file1_sbom, file1_path, apk_details)

        # 📥 Download SBOM JSON
        st.download_button(
            label="📥 Download SBOM JSON",
            data=json.dumps(file1_sbom, indent=4),
            file_name="generated_sbom.json",
            mime="application/json"
        )

        # 🔍 Fuzzy Search
        st.subheader("🔍 SBOM Fuzzy Search")
        search_query = st.text_input("Enter component, permission, or library to search", key="fuzzy_input")
        if search_query:
            results = fuzzy_search_components(file1_sbom, apk_details, search_query, threshold=80)
            if results:
                df = pd.DataFrame(results)
                st.success(f"✅ Found {len(results)} match(es)")
                st.dataframe(df)
                st.download_button("📥 Download CSV", df.to_csv(index=False), "fuzzy_search_results.csv", "text/csv")
            else:
                st.warning("No matches found.")

# ▶️ Parse SBOM File (Standalone JSON parsing)
elif parse_button and file1 and file1.name.endswith(".json"):
    file1_path = save_uploaded_file(file1)
    if file1_path:
        parsed_sbom = parse_sbom(file1_path)
        if parsed_sbom:
            st.success("✅ SBOM Parsed Successfully!")
            st.download_button("📥 Download Parsed SBOM", json.dumps(parsed_sbom, indent=4), "parsed_sbom.json", "application/json")
        else:
            st.error("❌ Failed to parse SBOM file.")



if compare_button:
    if not file1 or not file2:
        st.error("❌ Please upload two files for comparison.")
    else:
        file1_path = save_uploaded_file(file1)
        file2_path = save_uploaded_file(file2)

        file1_sbom, apk_details_1 = process_file(file1_path)
        file2_sbom, apk_details_2 = process_file(file2_path)

        if file1_sbom and file2_sbom:
            # --- 📄 Metadata Comparison ---
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
                st.markdown("**App 1 Metadata**")
                st.table(pd.DataFrame(meta1.items(), columns=["Attribute", "Value"]))
            with col2:
                st.markdown("**App 2 Metadata**")
                st.table(pd.DataFrame(meta2.items(), columns=["Attribute", "Value"]))

            # --- Permissions Comparison ---
            st.subheader("🔐 Permissions Comparison")
            col1, col2 = st.columns(2)
            with col1:
                st.markdown("**App 1 Permissions**")
                st.code("\n".join(apk_details_1.get("Permissions", [])) if apk_details_1 else "N/A")
            with col2:
                st.markdown("**App 2 Permissions**")
                st.code("\n".join(apk_details_2.get("Permissions", [])) if apk_details_2 else "N/A")

            # --- Library Comparison ---
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

            # --- Component Comparison ---
            st.subheader("🔄 Component Comparison Results")
            added, removed, modified = compare_sboms(file1_sbom, file2_sbom)

            if isinstance(modified, str):
                st.info(modified)
            else:
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown("### ✅ Added Components")
                    st.dataframe(pd.DataFrame(added)) if added else st.info("No new components added.")
                with col2:
                    st.markdown("### ❌ Removed Components")
                    st.dataframe(pd.DataFrame(removed)) if removed else st.info("No components removed.")

                st.markdown("### ✨ Modified Components")
                if modified:
                    for mod in modified:
                        st.write(f"**Component:** `{mod['Component']}`")
                        st.json({
                            "SBOM 1": mod["SBOM 1"],
                            "SBOM 2": mod["SBOM 2"]
                        })
                else:
                    st.info("No modified components found.")

            # 🛡️ VULNERABILITY & LICENSE CHECKS (For App 1)
            if apk_details_1:
                st.subheader("🛡️ App 1 Vulnerability & License Scan")
                vulnerabilities, licenses = scan_vulnerabilities_and_licenses(apk_details_1)

                if vulnerabilities:
                    for lib, vulns in vulnerabilities.items():
                        st.markdown(f"**{lib}**: {', '.join(vulns) if vulns else '✅ No known vulnerabilities'}")
                else:
                    st.info("No libraries detected for vulnerability scanning.")

                st.subheader("📜 License Compliance")
                if licenses:
                    for lib, license in licenses.items():
                        st.markdown(f"**{lib}**: `{license}`")
                else:
                    st.info("No libraries detected for license analysis.")
# Advanced features section
display_advanced_features()
st.info("Thank you for using SBOM Analyzer! 🚀 More features coming soon.")

