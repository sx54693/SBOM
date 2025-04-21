import os

def detect_binary_type(file_path):
    """Returns 'Mobile' for APKs, 'Desktop' for EXEs, or 'Unknown'."""
    ext = os.path.splitext(file_path)[-1].lower()
    if ext == ".apk":
        return "Mobile"
    elif ext == ".exe":
        return "Desktop"
    else:
        return "Unknown
