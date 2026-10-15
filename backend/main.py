
from fastapi import FastAPI

app = FastAPI(title="Network Attack Impact Analyzer")


@app.get("/")
def home():
    return {"message": "Network Attack Impact Analyzer API is running"}


@app.get("/health")
def health():
    return {"status": "ok"}
