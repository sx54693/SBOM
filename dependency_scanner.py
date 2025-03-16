import subprocess
import json

def scan_dependencies(file_path):
    """Scans for direct and transitive dependencies."""
    dependencies = {"direct": [], "transitive": []}

    if file_path.endswith(".exe"):
        print("⚠️ EXE files may not list dependencies directly. Try scanning extracted files.")
        return dependencies

    # Python dependencies
    if "requirements.txt" in file_path or file_path.endswith(".py"):
        try:
            result = subprocess.run(["pip", "list", "--format=json"], capture_output=True, text=True, check=True)
            dependencies["direct"] = json.loads(result.stdout)
        except Exception as e:
            print(f"❌ Python Dependency Scan Error: {e}")

    # Node.js dependencies
    elif "package.json" in file_path:
        try:
            result = subprocess.run(["npm", "list", "--json"], capture_output=True, text=True, check=True)
            npm_data = json.loads(result.stdout)
            dependencies["direct"] = list(npm_data.get("dependencies", {}).keys())
        except Exception as e:
            print(f"❌ NPM Dependency Scan Error: {e}")

    # Java dependencies
    elif "pom.xml" in file_path:
        try:
            result = subprocess.run(["mvn", "dependency:tree", "-DoutputType=json"], capture_output=True, text=True, check=True)
            dependencies["direct"] = json.loads(result.stdout)
        except Exception as e:
            print(f"❌ Maven Dependency Scan Error: {e}")

    return dependencies
