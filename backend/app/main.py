from fastapi import FastAPI
from app.api.auth import router as auth_router
from app.api.files import router as files_router

app = FastAPI(
    title="AegisVault",
    description="Zero-trust secure file storage backend.",
    version="1.0.0",
)

app.include_router(auth_router)
app.include_router(files_router)


@app.get("/health", tags=["Health"])
async def health_check() -> dict:
    return {"status": "ok"}