import streamlit as st
import os
import json
import requests
import pandas as pd
import subprocess
import platform
import pefile
from sbom_compare import compare_sboms
from sbom_parser import parse_sbom
from sbom_search import search_sbom

# Page Configuration
st.set_page_config(page_title="SBOM Analyzer", page_icon="🔍", layout="wide")

# UI Enhancement
st.markdown("""
    <style>
    .stApp { background: linear-gradient(135deg, #1f4037, #99f2c8); color: white; }
    [data-testid="stSidebar"] { background: #1f2833; color: white; }
    div.stButton > button { background-color: #008CBA; color: white; border-radius: 8px; }
    div.stButton > button:hover { background-color: #005f73; }
    </style>
""", unsafe_allow_html=True)

st.title("🔍 SBOM Analyzer")

# Sidebar
st.sidebar.header("📂 File Operations")
file1 = st.sidebar.file_uploader("🆕 Upload First File", type=["exe", "json", "spdx", "csv", "xml"])
file2 = st.sidebar.file_uploader("📑 Upload Second File for Comparison", type=["exe", "json", "spdx", "csv", "xml"])

generate_button = st.sidebar.button("🔄 Generate SBOM")
compare_button = st.sidebar.button("🔍 Compare SBOMs")
search_button = st.sidebar.button("🔎 Search SBOM Components")
parse_button = st.sidebar.button("📜 Parse SBOM")

API_URL = "https://sbom.onrender.com"

# Save uploaded files
def save_uploaded_file(uploaded_file, folder="uploaded_apps"):
    os.makedirs(folder, exist_ok=True)
    file_path = os.path.join(folder, uploaded_file.name)
    with open(file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    return file_path

# Display SBOM Data
def display_sbom_data(sbom_data):
    st.subheader("📄 SBOM Data")
    st.json(sbom_data, expanded=False)

# Backend API Call
def generate_sbom_backend(file_path):
    with open(file_path, "rb") as file:
        response = requests.post(f"{API_URL}/generate-sbom", files={"file": file})
        return response.json() if response.ok else None

# SBOM Generation
if generate_button and file1:
    path = save_uploaded_file(file1)
    sbom_data = generate_sbom_backend(path)
    if sbom_data:
        display_sbom_data(sbom_data)
    else:
        st.error("❌ SBOM Generation Failed.")

# SBOM Comparison
if compare_button and file1 and file2:
    path1 = save_uploaded_file(file1)
    path2 = save_uploaded_file(file2)
    added, removed, error = compare_sboms(path1, path2)

    if error:
        st.error(error)
    else:
        st.subheader("🟢 Added Components")
        st.write(added or "None")
        st.subheader("🔴 Removed Components")
        st.write(removed or "None")

# SBOM Component Search
if search_button and file1:
    path = save_uploaded_file(file1)
    query = st.text_input("Enter component name to search:")
    if query:
        results = search_sbom(path, query)
        st.subheader("🔎 Search Results")
        st.write(results or "No matching components found.")

# SBOM Parsing
if parse_button and file1:
    path = save_uploaded_file(file1)
    parsed_data, error = parse_sbom(path)

    if error:
        st.error(error)
    else:
        st.subheader("📜 Parsed SBOM Data")
        st.write(parsed_data)
