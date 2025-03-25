from fastapi import FastAPI, UploadFile, File
from sbom_generator import generate_sbom
import json, os

app = FastAPI()

@app.post("/generate-sbom/")
async def generate_sbom_api(file: UploadFile = File(...)):
    file_location = f"uploaded_apps/{file.filename}"
    os.makedirs("uploaded_apps", exist_ok=True)

    with open(file_location, "wb") as buffer:
        buffer.write(await file.read())

    sbom_output_path = generate_sbom(file_location)

    if not sbom_output_path:
        return {"error": "SBOM generation failed"}

    with open(sbom_output_path, "r", encoding="utf-8") as sbom_file:
        sbom_json = json.load(sbom_file)

    return sbom_json
from fastapi import FastAPI

app = FastAPI()

@app.get("/")
async def root():
    return {"status": "SBOM API is running ✅"}
