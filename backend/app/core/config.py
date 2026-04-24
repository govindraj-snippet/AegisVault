from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # --- existing ---
    DATABASE_URL: str
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # --- new for Module 3 ---
    AWS_ACCESS_KEY_ID: str
    AWS_SECRET_ACCESS_KEY: str
    AWS_REGION: str = "auto"          # Cloudflare R2 uses "auto"
    S3_BUCKET_NAME: str
    S3_ENDPOINT_URL: str              # e.g. https://<account>.r2.cloudflarestorage.com

    class Config:
        env_file = ".env"

settings = Settings()