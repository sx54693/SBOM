from fastapi import FastAPI
from sbom_generator import generate_sbom

app = FastAPI()

@app.get("/")
def root():
    return {"message": "✅ SBOM API is working at /generate-sbom/"}

# Register your SBOM endpoint
app.post("/generate-sbom/")(generate_sbom)
