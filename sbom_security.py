vulnerability_db = {
    "androidx": ["CVE-2023-12345", "CVE-2022-67890"],
    "com.bumptech.glide": ["CVE-2021-11111"],
    "io.reactivex": ["CVE-2020-55555"],
    "msvcrt.dll": ["CVE-2019-00001"],
    "kernel32.dll": ["CVE-2021-99999"]
}

license_db = {
    "androidx": "Apache-2.0",
    "com.bumptech.glide": "BSD-2-Clause",
    "io.reactivex": "MIT",
    "javax": "GPL-2.0",
    "kotlin": "Apache-2.0",
    "msvcrt.dll": "Proprietary",
    "kernel32.dll": "Proprietary"
}

def scan_vulnerabilities_and_licenses(details):
    libraries = details.get("Libraries", [])
    normalized_libs = [lib.lower().strip() for lib in libraries]

    vulnerabilities = {}
    licenses = {}

    for lib in normalized_libs:
        vulnerabilities[lib] = vulnerability_db.get(lib, [])
        licenses[lib] = license_db.get(lib, "Unknown")

    return vulnerabilities, licenses
