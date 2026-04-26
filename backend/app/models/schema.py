import uuid
from sqlalchemy import String, Boolean, ForeignKey, Text, Integer
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
from app.models.database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    account_status: Mapped[str] = mapped_column(String(20), nullable=False, default="ACTIVE")

    files: Mapped[list["File"]] = relationship(
        "File", back_populates="owner", cascade="all, delete-orphan"
    )


class File(Base):
    __tablename__ = "files"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False, index=True
    )
    filename: Mapped[str] = mapped_column(String(512), nullable=False)
    cloud_url: Mapped[str] = mapped_column(Text, nullable=False)
    aes_key: Mapped[str] = mapped_column(Text, nullable=False)
    is_quarantined: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # ── NEW ──────────────────────────────────────────────────────────────────
    # Stores the RAW file size in bytes (pre-encryption).
    # We store the original size, not the ciphertext size, so quota reflects
    # what the user actually uploaded, not our encryption overhead (nonce + tag).
    file_size: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    owner: Mapped["User"] = relationship("User", back_populates="files")