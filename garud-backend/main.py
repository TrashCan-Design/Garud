from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from scanner_engine import perform_scan

app = FastAPI(title="Garud Scanner API")


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    url: str

@app.get("/")
def home():
    return {"system": "Garud Vulnerability Scanner", "status": "Active"}


@app.post("/api/scan")
async def start_scan(request: ScanRequest):
    
    if not request.url.startswith("http"):
        return {"status": "error", "message": "Invalid URL scheme. Use http:// or https://"}
    
    results = perform_scan(request.url)
    return results

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)