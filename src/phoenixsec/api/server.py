from fastapi import FastAPI

app = FastAPI(title="PhoenixSec API")


@app.get("/")
def read_root():
    return {"message": "PhoenixSec API is running"}
