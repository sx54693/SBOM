import pefile

file_path = "uploaded_apps/TeamViewerQS_x64.exe"

try:
    pe = pefile.PE(file_path)

    print("\n✅ Extracting metadata from:", file_path)

    if hasattr(pe, "FileInfo"):
        for file_info in pe.FileInfo:
            if isinstance(file_info, list):
                for entry in file_info:
                    if hasattr(entry, "StringTable"):
                        for st in entry.StringTable:
                            for key, value in st.entries.items():
                                key = key.decode("utf-8", "ignore")
                                value = value.decode("utf-8", "ignore")

                                print(f"{key}: {value}")  # Print all metadata

except Exception as e:
    print(f"❌ EXE Metadata Extraction Failed: {e}")
