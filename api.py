from fastapi import FastAPI, UploadFile, File
import subprocess, json, tempfile, shutil

app = FastAPI()

@app.post("/generate-sbom/")
async def generate_sbom(file: UploadFile = File(...)):
    with tempfile.TemporaryDirectory() as tempdir:
        file_path = f"{tempdir}/{file.filename}"
        with open(file_path, "wb") as f:
            shutil.copyfileobj(file.file, f)

        result = subprocess.run(["syft", file_path, "-o", "cyclonedx-json"], capture_output=True, text=True)

        if result.returncode != 0:
            return {"error": result.stderr}

        sbom_json = json.loads(result.stdout)
        return sbom_json
