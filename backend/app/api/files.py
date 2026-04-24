import uuid
from typing import Annotated, AsyncGenerator

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import get_current_user
from app.models.database import get_db
from app.models.schema import File as FileModel, User
from app.services.crypto import encrypt_file, decrypt_file
from app.services.storage import upload_ciphertext, download_ciphertext_stream

router = APIRouter(prefix="/files", tags=["Files"])


# ── Pydantic Schemas ─────────────────────────────────────────────────────────

class FileUploadResponse(BaseModel):
    file_id: uuid.UUID
    filename: str
    cloud_url: str
    message: str = "File encrypted and uploaded successfully."

class FileMetaResponse(BaseModel):
    file_id: uuid.UUID
    filename: str
    cloud_url: str
    is_quarantined: bool

    model_config = {"from_attributes": True}


# ── Helpers ──────────────────────────────────────────────────────────────────

def _object_key(user_id: uuid.UUID, file_id: uuid.UUID, filename: str) -> str:
    """
    Builds a deterministic S3 object key scoped to the owning user.
    Layout: users/<user_id>/files/<file_id>/<filename>
    Prevents any possibility of cross-user key collisions.
    """
    return f"users/{user_id}/files/{file_id}/{filename}"


async def _collect_stream(stream: AsyncGenerator[bytes, None]) -> bytes:
    """
    Fully buffers an async byte stream into memory.
    Used only on download where we must decrypt the full ciphertext
    before returning plaintext — GCM tag verification requires the
    entire payload.
    """
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
    Pipeline:
      1. Read raw bytes from multipart upload.
      2. Encrypt with AES-256-GCM (fresh key per file).
      3. Upload ciphertext to S3/R2.
      4. Persist file metadata + AES key to Postgres.

    The AES key never leaves the DB unencrypted — Module 5 (KMS wrapping)
    will add envelope encryption on top of this column.
    """
    raw_bytes: bytes = await file.read()

    if not raw_bytes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty.",
        )

    # Step 1 — Encrypt
    ciphertext, aes_key = encrypt_file(raw_bytes)

    # Step 2 — Build a stable S3 key before upload so it can be stored in DB
    file_id = uuid.uuid4()
    object_key = _object_key(current_user.id, file_id, file.filename or "unnamed")

    # Step 3 — Upload ciphertext; raises HTTP 502 on failure
    cloud_url = await upload_ciphertext(object_key, ciphertext)

    # Step 4 — Persist metadata; DB commit is handled by get_db() context manager
    file_record = FileModel(
        id=file_id,
        user_id=current_user.id,
        filename=file.filename or "unnamed",
        cloud_url=cloud_url,
        aes_key=aes_key,
        is_quarantined=False,
    )
    db.add(file_record)
    await db.flush()

    return FileUploadResponse(
        file_id=file_record.id,
        filename=file_record.filename,
        cloud_url=file_record.cloud_url,
    )


@router.get("/download/{file_id}")
async def download_file(
    file_id: uuid.UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> StreamingResponse:
    """
    Pipeline:
      1. Fetch file record from DB — 404 if not found.
      2. Ownership check — 403 if the requesting user does not own it.
      3. Quarantine gate — 403 if flagged by the threat scanner.
      4. Fetch ciphertext stream from S3/R2.
      5. Buffer + decrypt with stored AES key.
      6. Stream plaintext back to client.

    Security ordering is intentional: ownership is verified before
    quarantine status to avoid leaking whether a file_id exists at all
    to non-owners.
    """
    # Step 1 — Fetch record
    result = await db.execute(
        select(FileModel).where(FileModel.id == file_id)
    )
    file_record: FileModel | None = result.scalar_one_or_none()

    if file_record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found.",
        )

    # Step 2 — Ownership gate
    if file_record.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to access this file.",
        )

    # Step 3 — Quarantine gate
    if file_record.is_quarantined:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This file has been quarantined and cannot be downloaded.",
        )

    # Step 4 — Reconstruct object key and fetch ciphertext
    object_key = _object_key(file_record.user_id, file_record.id, file_record.filename)
    ciphertext = await _collect_stream(download_ciphertext_stream(object_key))

    # Step 5 — Decrypt; raises HTTP 422 on tag mismatch / tampering
    try:
        plaintext = decrypt_file(ciphertext, file_record.aes_key)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"File decryption failed. The file may be corrupted: {exc}",
        )

    # Step 6 — Stream plaintext to client
    async def plaintext_generator() -> AsyncGenerator[bytes, None]:
        chunk_size = 1024 * 256  # 256 KB chunks
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
    """
    Returns metadata for all files owned by the authenticated user.
    AES keys are never included in any list or detail response.
    """
    result = await db.execute(
        select(FileModel).where(FileModel.user_id == current_user.id)
    )
    files = result.scalars().all()
    return [FileMetaResponse.model_validate(f) for f in files]