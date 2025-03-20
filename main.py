from fastapi import FastAPI, UploadFile, File
import json
import os

app = FastAPI()

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.get("/")
def home():
    return {"message": "FastAPI Backend is Running!"}

# ✅ SBOM Generation Endpoint
@app.post("/generate-sbom")
async def generate_sbom(file: UploadFile = File(...)):
    file_path = os.path.join(UPLOAD_FOLDER, file.filename)

    # Save the uploaded file
    with open(file_path, "wb") as f:
        f.write(await file.read())

    # ✅ Simulated SBOM output (Replace this with actual SBOM generation logic)
    sbom_data = {
        "filename": file.filename,
        "sbom_components": ["Component1", "Component2", "Component3"]
    }

    return sbom_data

# ✅ SBOM Comparison Endpoint
@app.post("/compare-sbom")
async def compare_sbom(file1: UploadFile = File(...), file2: UploadFile = File(...)):
    return {"message": "SBOM comparison logic will go here"}
 
