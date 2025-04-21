# SBOM Analyzer for Software Applications and Apps

## Overview
The **SBOM Finder** is a Minimally Viable Product (MVP) built to generate, analyze, and compare Software Bill of Materials (SBOMs) for desktop and mobile applications. It supports multiple SBOM formats (CycloneDX and SPDX), performs fuzzy component search, and enables side-by-side comparisons with a modern web interface powered by Streamlit.

## Features
- **SBOM Generation**: Automatically generates CycloneDX JSON SBOMs using Syft.
- **SBOM Comparison**: Compares two applications' SBOMs and highlights added/removed components.
- **Fuzzy Component Search**: Uses fuzzy matching to find components by name across parsed SBOM data.
- **Platform Detection**: Identifies whether uploaded binaries are desktop (.exe) or mobile (.apk).
- **Metadata Extraction**: Pulls out app metadata, permissions, libraries, and smali packages.
- **Library Inference**: Uses apktool and aapt to extract Android app details (e.g., permissions, native libs).
- **Advanced UI**: Streamlit interface with toggles, uploads, and custom visual comparison sections.
- **API Integration Ready**: Modular backend designed to integrate with FastAPI (in development).
- **Cross-format Support**: Parsing support added for CycloneDX XML SBOMs.

## Installation and Setup

### Prerequisites
- Python 3.8+
- Git
- Streamlit Cloud or Localhost (CLI)

### Installation
```bash
git clone https://github.com/sx54693/sbom.git
cd sbom
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Run the App
```bash
streamlit run app.py
```

> ✅ Note: `apktool`, `aapt`, and `7z` binaries are required for APK analysis and must be available in the system path. On Streamlit Cloud, these tools are not supported — features will degrade gracefully with warnings.

## Usage

- **Generate SBOM**: Upload `.exe`, `.apk`, or `.json` file and click "Generate SBOM".
- **Compare Applications**: Upload two files to compare and click "Compare SBOMs".
- **Search Components**: Type part of a library name (e.g., `androidx`, `kotlin`) to perform fuzzy matching.

## REST API (Planned for Beta)
To run with FastAPI (for future REST support):
```bash
uvicorn app:main --host 0.0.0.0 --port 8000
```

## Deployment
- **Local Deployment**: Fully supported using Streamlit and local Python environment.
- **Cloud Deployment**: Streamlit Cloud supported (with limited APK feature compatibility).
- **Advanced**: GCP or EC2 VM recommended for full toolchain support (apktool, 7z, aapt).

## Contributing
- Fork the repository
- Create a feature branch: `git checkout -b feature-xyz`
- Commit and push changes
- Open a Pull Request

## License
MIT License

## Contact
For support or inquiries, reach out to: [cyriackurian123](https://github.com/cyriackurian123) or open a GitHub issue.

---

## Authors
- [@sx54693](https://github.com/sx54693)
- [@cyriackurian123](https://github.com/cyriackurian123)

---

**Languages Used:**
- Python 99.2%
- Shell 0.8%

## Tech Stack
- Streamlit (Frontend/UI)
- Python (Core logic)
- apktool / aapt / 7z (External tools for APK/EXE analysis)
