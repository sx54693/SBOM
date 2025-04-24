
# SBOM Analyzer for Software Applications and Apps

## Overview
The **SBOM Finder** is a **Minimally Viable Product (MVP)** designed to generate, analyze, and compare Software Bill of Materials (SBOMs) for desktop and mobile applications. It supports multiple SBOM formats (**CycloneDX**, **SPDX**), enables fuzzy component search, and offers side-by-side SBOM comparisons through a modern web interface powered by **Streamlit**.

## Features
- **SBOM Generation**: Generate CycloneDX JSON SBOMs using **Syft**.
- **SBOM Comparison**: Highlight added/removed components between two SBOMs.
- **Fuzzy Component Search**: Find components via fuzzy matching.
- **Platform Detection**: Auto-detect desktop (`.exe`) or mobile (`.apk`) binaries.
- **Metadata Extraction**: Extract app metadata, permissions, libraries, and smali packages.
- **Library Inference**: Use **apktool**, **aapt**, and **7z** for Android analysis.
- **Advanced UI**: Interactive **Streamlit** interface with upload, toggles, and comparison views.
- **API Integration Ready**: Backend modularity for future integration.
- **Cross-format Support**: Supports parsing CycloneDX XML SBOMs.
- **Docker Support**: Containerized deployment for consistent environment setup.

## Installation and Setup

### Prerequisites
- Python 3.8+
- Git
- Docker (for containerized deployment)
- Optional: Local installation of `apktool`, `aapt`, `7z` for full APK/EXE analysis.

### Clone the Repository
```bash
git clone https://github.com/sx54693/sbom.git
cd sbom
```

### Local Installation
```bash
python -m venv venv
# Activate Virtual Environment
source venv/bin/activate    # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Run the App Locally
```bash
streamlit run app.py
```

> ✅ **Note:** For APK analysis, ensure `apktool`, `aapt`, and `7z` are available in your system path. On Streamlit Cloud, APK features will degrade gracefully with warnings.

## Docker Deployment

### Build Docker Image
```bash
docker build -t sbom-analyzer .
```

### Run Docker Container
```bash
docker run -d -p 8501:8501 sbom-analyzer
```

Access the app at: `http://localhost:8501`

## Usage
- **Generate SBOM**: Upload `.exe`, `.apk`, or `.json` and click **"Generate SBOM"**.
- **Compare Applications**: Upload two files and click **"Compare SBOMs"**.
- **Search Components**: Use fuzzy search to find libraries (e.g., `androidx`, `kotlin`).

## Deployment Options
- **Local**: Full support via Streamlit.
- **Streamlit Cloud**: Limited APK feature compatibility.
- **Advanced**: Deploy on **GCP**, **AWS EC2**, or Docker for complete toolchain support.

## Contributing
1. Fork this repo
2. Create a feature branch:
   ```bash
   git checkout -b feature-xyz
   ```
3. Commit & push changes
4. Open a Pull Request

## License
This project is licensed under the **MIT License**.

## Contact
For support or queries:
- GitHub: [@cyriackurian123](https://github.com/cyriackurian123)  
- Or open a GitHub issue.

## Authors
- [@sx54693](https://github.com/sx54693)
- [@cyriackurian123](https://github.com/cyriackurian123)

## Languages Used
- **Python**: 99.2%
- **Shell**: 0.8%

## Tech Stack
- **Frontend/UI**: Streamlit
- **Core Logic**: Python
- **External Tools**: apktool, aapt, 7z

