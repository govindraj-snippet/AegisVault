import uuid
from typing import Annotated, AsyncGenerator

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import get_current_user
from app.models.database import get_db
from app.models.schema import File as FileModel, User
from app.services.crypto import encrypt_file, decrypt_file
from app.services.storage import upload_ciphertext, download_ciphertext_stream

router = APIRouter(prefix="/files", tags=["Files"])

# 100 MB hard ceiling in bytes
_QUOTA_BYTES = 104_857_600


# ── Pydantic Schemas ─────────────────────────────────────────────────────────

class FileUploadResponse(BaseModel):
    file_id: uuid.UUID
    filename: str
    cloud_url: str
    file_size: int
    message: str = "File encrypted and uploaded successfully."


class FileMetaResponse(BaseModel):
    file_id: uuid.UUID
    filename: str
    cloud_url: str
    file_size: int
    is_quarantined: bool

    model_config = {"from_attributes": True}


# ── Helpers ──────────────────────────────────────────────────────────────────

def _object_key(user_id: uuid.UUID, file_id: uuid.UUID, filename: str) -> str:
    return f"users/{user_id}/files/{file_id}/{filename}"


async def _get_used_storage(user_id: uuid.UUID, db: AsyncSession) -> int:
    """
    Issues a single SUM() aggregate to Postgres instead of fetching all
    file rows and summing in Python. Crucial for correctness at scale —
    a user with 10,000 files should not cause 10,000 rows to be
    transferred over the wire just to enforce a quota.

    Returns 0 if the user has no files yet (coalesce handles NULL).
    """
    result = await db.execute(
        select(func.coalesce(func.sum(FileModel.file_size), 0))
        .where(FileModel.user_id == user_id)
    )
    return int(result.scalar_one())


async def _collect_stream(stream: AsyncGenerator[bytes, None]) -> bytes:
    chunks: list[bytes] = []
    async for chunk in stream:
        chunks.append(chunk)
    return b"".join(chunks)


# ── Routes ───────────────────────────────────────────────────────────────────

@router.post(
    "/upload",
    response_model=FileUploadResponse,
    status_code=status.HTTP_201_CREATED,
)
async def upload_file(
    file: Annotated[UploadFile, File(description="Binary file to encrypt and store.")],
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> FileUploadResponse:
    """
    Upload pipeline with quota enforcement:

      0. Read Content-Length header for a cheap pre-flight size check.
      1. Read raw bytes — required before we can encrypt or know exact size.
      2. Quota gate: SUM(existing file_size) + incoming size vs 100 MB ceiling.
      3. Encrypt with AES-256-GCM.
      4. Upload ciphertext to S3/R2.
      5. Persist metadata including file_size to Postgres.

    Quota is checked AFTER reading bytes (step 2) because multipart uploads
    do not guarantee a reliable Content-Length header. We use the actual
    byte count as the source of truth.
    """

    # Step 1 — Read raw bytes
    raw_bytes: bytes = await file.read()

    if not raw_bytes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty.",
        )

    incoming_size: int = len(raw_bytes)

    # Step 2 — Quota gate (single async DB aggregate — never blocks the loop)
    used_bytes = await _get_used_storage(current_user.id, db)

    if used_bytes + incoming_size > _QUOTA_BYTES:
        remaining = max(_QUOTA_BYTES - used_bytes, 0)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Storage quota exceeded. "
                f"You have {remaining:,} bytes remaining of your "
                f"{_QUOTA_BYTES:,} byte (100 MB) quota."
            ),
        )

    # Step 3 — Encrypt
    ciphertext, aes_key = encrypt_file(raw_bytes)

    # Step 4 — Upload ciphertext to S3/R2
    file_id = uuid.uuid4()
    object_key = _object_key(current_user.id, file_id, file.filename or "unnamed")
    cloud_url = await upload_ciphertext(object_key, ciphertext)

    # Step 5 — Persist metadata
    file_record = FileModel(
        id=file_id,
        user_id=current_user.id,
        filename=file.filename or "unnamed",
        cloud_url=cloud_url,
        aes_key=aes_key,
        is_quarantined=False,
        file_size=incoming_size,       # raw bytes, not ciphertext size
    )
    db.add(file_record)
    await db.flush()

    return FileUploadResponse(
        file_id=file_record.id,
        filename=file_record.filename,
        cloud_url=file_record.cloud_url,
        file_size=file_record.file_size,
    )


@router.get("/download/{file_id}")
async def download_file(
    file_id: uuid.UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> StreamingResponse:
    """
    Download pipeline (unchanged from Module 3 except FileModel now carries file_size):

      1. Fetch file record — 404 if missing.
      2. Ownership gate — 403 if not owner.
      3. Quarantine gate — 403 if flagged.
      4. Fetch + buffer ciphertext from S3/R2.
      5. Decrypt with stored AES key.
      6. Stream plaintext back to client.
    """
    result = await db.execute(
        select(FileModel).where(FileModel.id == file_id)
    )
    file_record: FileModel | None = result.scalar_one_or_none()

    if file_record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found.")

    if file_record.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to access this file.",
        )

    if file_record.is_quarantined:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This file has been quarantined and cannot be downloaded.",
        )

    object_key = _object_key(file_record.user_id, file_record.id, file_record.filename)
    ciphertext = await _collect_stream(download_ciphertext_stream(object_key))

    try:
        plaintext = decrypt_file(ciphertext, file_record.aes_key)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"File decryption failed. The file may be corrupted: {exc}",
        )

    async def plaintext_generator() -> AsyncGenerator[bytes, None]:
        chunk_size = 1024 * 256
        for i in range(0, len(plaintext), chunk_size):
            yield plaintext[i : i + chunk_size]

    return StreamingResponse(
        plaintext_generator(),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{file_record.filename}"',
            "Content-Length": str(len(plaintext)),
        },
    )


@router.get("/my-files", response_model=list[FileMetaResponse])
async def list_my_files(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[FileMetaResponse]:
    result = await db.execute(
        select(FileModel).where(FileModel.user_id == current_user.id)
    )
    files = result.scalars().all()
    return [FileMetaResponse.model_validate(f) for f in files]


@router.get("/storage-usage")
async def storage_usage(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """
    Returns the user's current storage consumption against their quota.
    Cheap aggregate query — no file rows transferred.
    """
    used = await _get_used_storage(current_user.id, db)
    return {
        "used_bytes": used,
        "quota_bytes": _QUOTA_BYTES,
        "remaining_bytes": max(_QUOTA_BYTES - used, 0),
        "used_percent": round((used / _QUOTA_BYTES) * 100, 2),
    }