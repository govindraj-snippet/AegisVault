from typing import AsyncGenerator
import aioboto3
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import HTTPException, status

from app.core.config import settings

# One session reused across the app lifetime — not recreated per request
_session = aioboto3.Session()


def _s3_client():
    """
    Returns an async context manager that yields a ready S3 client.
    Using a helper keeps the credential config in one place and
    lets callers use `async with _s3_client() as s3:` cleanly.
    """
    return _session.client(
        "s3",
        region_name=settings.AWS_REGION,
        endpoint_url=settings.S3_ENDPOINT_URL,
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
    )


async def upload_ciphertext(object_key: str, ciphertext: bytes) -> str:
    """
    Uploads raw ciphertext bytes to S3/R2.

    Returns:
        The canonical cloud URL for the stored object.

    Raises:
        HTTP 502 on any S3-side failure — never leaks boto internals to caller.
    """
    try:
        async with _s3_client() as s3:
            await s3.put_object(
                Bucket=settings.S3_BUCKET_NAME,
                Key=object_key,
                Body=ciphertext,
                ContentType="application/octet-stream",
            )
    except (BotoCoreError, ClientError) as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Storage backend error during upload: {exc}",
        )

    # Construct a stable URL — does not rely on S3 presigned URLs
    return f"{settings.S3_ENDPOINT_URL}/{settings.S3_BUCKET_NAME}/{object_key}"


async def download_ciphertext_stream(object_key: str) -> AsyncGenerator[bytes, None]:
    """
    Streams ciphertext from S3/R2 as an async byte generator.

    Designed to feed directly into FastAPI's StreamingResponse so we
    never buffer the entire file in memory on download.

    Raises:
        HTTP 404 if the object key does not exist in the bucket.
        HTTP 502 on any other S3-side failure.
    """
    try:
        async with _s3_client() as s3:
            response = await s3.get_object(
                Bucket=settings.S3_BUCKET_NAME,
                Key=object_key,
            )
            async for chunk in response["Body"].iter_chunks(chunk_size=1024 * 256):
                yield chunk

    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        if error_code == "NoSuchKey":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="File not found in storage backend.",
            )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Storage backend error during download: {exc}",
        )
    except BotoCoreError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Storage backend connection error: {exc}",
        )


async def delete_object(object_key: str) -> None:
    """
    Deletes an object from S3/R2.
    Silent no-op if the key does not exist (S3 delete is idempotent).

    Raises:
        HTTP 502 on hard S3-side failures.
    """
    try:
        async with _s3_client() as s3:
            await s3.delete_object(
                Bucket=settings.S3_BUCKET_NAME,
                Key=object_key,
            )
    except (BotoCoreError, ClientError) as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Storage backend error during delete: {exc}",
        )