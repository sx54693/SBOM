from sbom_generator import app
@app.get("/")
def root():
    return {"message": "✅ SBOM API is working"}
