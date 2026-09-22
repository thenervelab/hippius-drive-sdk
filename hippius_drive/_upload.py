"""Turning a local file into a signed manifest plus an encrypted blob.

Plaintext is read once: ``salted_hash`` is taken from the same bytes that
are encrypted, then the ciphertext is spooled so the signed manifest can
go out ahead of the body. Small blobs stay in memory; larger ones spill
to a temp file instead of growing unbounded.
"""

from __future__ import annotations

import io
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from tempfile import SpooledTemporaryFile
from types import TracebackType
from typing import IO, TYPE_CHECKING

import blake3

if TYPE_CHECKING:
    from _typeshed import WriteableBuffer

from hippius_drive.crypto import file_cipher, hashes
from hippius_drive.identity import Identity
from hippius_drive.models import Manifest

TRANSPORT_CHUNK = 8 * 1024 * 1024
"""Bytes per chunk on the session path, matching hcfs-client's UPLOAD_CHUNK_SIZE."""

SPOOL_MAX = TRANSPORT_CHUNK
"""Blobs up to this size stay in memory; larger ones spill to a temp file."""

DEFAULT_SOURCE = "python-sdk"
"""Client family reported for analytics. Unknown values land in the "other" bucket."""


@dataclass(frozen=True)
class PlaintextSource:
    """A plaintext that can be read twice.

    Attributes:
        open: Returns a fresh reader positioned at the start.
        size: Exact plaintext length, which fixes the frame count.
    """

    open: Callable[[], IO[bytes]]
    size: int

    @classmethod
    def from_path(cls, path: Path) -> PlaintextSource:
        """Read the plaintext from a file on disk.

        Args:
            path: The local file to upload.

        Returns:
            The source.
        """
        size = path.stat().st_size
        return cls(open=lambda: path.open("rb"), size=size)

    @classmethod
    def from_bytes(cls, data: bytes) -> PlaintextSource:
        """Read the plaintext from an in-memory buffer.

        Args:
            data: The bytes to upload.

        Returns:
            The source.
        """
        return cls(open=lambda: io.BytesIO(data), size=len(data))


@dataclass(frozen=True)
class UploadSpec:
    """Everything about an upload that is not the bytes themselves.

    Attributes:
        relative_path: Folder-relative POSIX path; normalised to NFC.
        base_revision_id: The revision this write replaces, or None for a new
            file. The server rejects a mismatch with 409.
        revision_seq: Must be strictly greater than the row's current value.
            Defaults to 1 for a new file; required when replacing one, because
            guessing it would either 400 or clobber a concurrent write.
        source: Client family, for the source summary.
    """

    relative_path: str
    base_revision_id: bytes | None = None
    revision_seq: int | None = None
    source: str = DEFAULT_SOURCE


class PreparedUpload:
    """A signed manifest plus the encrypted blob it describes.

    The blob lives in a spooled temp file that the caller must close, so use
    this as a context manager.

    Attributes:
        manifest: The signed manifest.
        ciphertext_size: Exact blob length, framing included.
    """

    def __init__(self, manifest: Manifest, blob: IO[bytes], ciphertext_size: int) -> None:
        """Build the prepared upload.

        Args:
            manifest: The signed manifest.
            blob: The encrypted blob, positioned at the start.
            ciphertext_size: Exact blob length.
        """
        self.manifest = manifest
        self.ciphertext_size = ciphertext_size
        self._blob = blob

    @property
    def blob(self) -> IO[bytes]:
        """The encrypted blob, rewound to the start."""
        self._blob.seek(0)
        return self._blob

    def read_chunk(self, index: int, chunk_size: int = TRANSPORT_CHUNK) -> bytes:
        """Return one transport chunk of the blob.

        Args:
            index: Zero-based transport chunk index.
            chunk_size: Bytes per chunk.

        Returns:
            The chunk; the last one may be shorter.
        """
        self._blob.seek(index * chunk_size)
        return self._blob.read(chunk_size)

    def transport_chunk_count(self, chunk_size: int = TRANSPORT_CHUNK) -> int:
        """How many transport chunks the blob occupies; never zero.

        Args:
            chunk_size: Bytes per chunk.

        Returns:
            The chunk count.
        """
        return max(1, -(-self.ciphertext_size // chunk_size))

    def close(self) -> None:
        """Release the spooled temp file."""
        self._blob.close()

    def __enter__(self) -> PreparedUpload:
        """Return self so the blob is always released."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Release the spooled temp file on the way out."""
        self.close()


class _SizedReader:
    """Cap a reader at ``size`` bytes and hash whatever is actually encrypted.

    ``encrypt_stream`` reads ``CHUNK_SIZE`` per full frame. A file that grew
    after ``stat`` would otherwise contribute extra bytes to a to-EOF hash
    while the ciphertext stopped at the declared size. Capping the read and
    then peeking one extra byte makes that a ``ValueError`` instead.
    """

    def __init__(self, inner: IO[bytes], size: int, hasher: blake3.blake3) -> None:
        self._inner = inner
        self._left = size
        self._hasher = hasher

    def read(self, size: int = -1) -> bytes:
        """Read up to ``size`` bytes, not past the declared plaintext length."""
        if self._left <= 0:
            return b""
        want = self._left if size < 0 else min(size, self._left)
        data = self._inner.read(want)
        self._left -= len(data)
        self._hasher.update(data)
        return data

    def reject_if_grown(self, declared: int) -> None:
        """Raise if the inner stream still has bytes past ``declared``."""
        if self._inner.read(1):
            raise ValueError(
                f"declared plaintext_size {declared}, file grew while it was being read"
            )


def _encrypt_to_spool(
    source: PlaintextSource, key: bytes, account_ss58: str
) -> tuple[IO[bytes], str, int, bytes]:
    """Encrypt into a spool, hashing plaintext and ciphertext from the same read."""
    # Not a context manager: the blob outlives this function and is closed by
    # PreparedUpload, whose caller owns it for the length of the upload.
    blob: IO[bytes] = SpooledTemporaryFile(max_size=SPOOL_MAX)  # noqa: SIM115
    cipher_hasher = blake3.blake3()
    salted = hashes.salted_hasher(account_ss58)
    written = 0
    try:
        with source.open() as reader:
            bounded = _SizedReader(reader, source.size, salted)
            for frame in file_cipher.encrypt_stream(bounded, key, source.size):
                cipher_hasher.update(frame)
                blob.write(frame)
                written += len(frame)
            bounded.reject_if_grown(source.size)
    except BaseException:
        blob.close()
        raise
    blob.seek(0)
    return blob, cipher_hasher.hexdigest(), written, salted.digest()


def _revision_seq(spec: UploadSpec) -> int:
    if spec.base_revision_id is None:
        return spec.revision_seq if spec.revision_seq is not None else 1
    if spec.revision_seq is None:
        raise ValueError(
            "replacing a file needs revision_seq (the current seq + 1); "
            "read it from files.state() rather than guessing"
        )
    return spec.revision_seq


def prepare(identity: Identity, source: PlaintextSource, spec: UploadSpec) -> PreparedUpload:
    """Encrypt ``source`` and build the manifest that describes it.

    Args:
        identity: The account and folder identity that signs the manifest.
        source: The plaintext; hashed and encrypted in one pass.
        spec: Path, revision, and source metadata.

    Returns:
        The prepared upload; close it, or use it as a context manager.

    Raises:
        ValueError: If the relative path is invalid, a replacement was
            requested without a ``revision_seq``, or the identity is a reader.
    """
    identity.require_writer()
    relative_path = hashes.normalize_relative_path(spec.relative_path)
    revision_seq = _revision_seq(spec)
    key = identity.encryption_key

    blob, ciphertext_hash, ciphertext_size, salted = _encrypt_to_spool(
        source, key, identity.account_ss58
    )

    manifest = Manifest(
        ss58_address=identity.account_ss58,
        folder_hash=identity.folder_hash,
        ciphertext_hash=ciphertext_hash,
        size_bytes=source.size,
        timestamp=int(time.time()),
        signature=identity.sign_ciphertext_hash(ciphertext_hash),
        signing_key=identity.verifying_key,
        path_hash=hashes.path_hash(relative_path),
        salted_hash=salted,
        revision_seq=revision_seq,
        base_revision_id=spec.base_revision_id,
        encrypted_path=file_cipher.encrypt_bytes(relative_path.encode(), key),
        file_name=relative_path.rsplit("/", 1)[-1],
        relative_path=relative_path,
        source=spec.source,
    )
    return PreparedUpload(manifest, blob, ciphertext_size)


class IteratorStream(io.RawIOBase):
    """A readable binary stream over an iterator of byte chunks.

    Lets the frame decoder pull from an httpx streaming response without the
    whole ciphertext ever being resident.
    """

    def __init__(self, chunks: Iterator[bytes]) -> None:
        """Build the stream.

        Args:
            chunks: The byte chunks to serve, in order.
        """
        self._chunks = chunks
        self._buffer = bytearray()
        self._exhausted = False

    def readable(self) -> bool:
        """Report that this stream can be read."""
        return True

    def readinto(self, buffer: WriteableBuffer, /) -> int:
        """Fill ``buffer`` from the iterator, returning how many bytes landed.

        Args:
            buffer: The destination buffer.

        Returns:
            Bytes written; 0 at end of stream.
        """
        view = memoryview(buffer).cast("B")
        wanted = len(view)
        while len(self._buffer) < wanted and not self._exhausted:
            try:
                self._buffer.extend(next(self._chunks))
            except StopIteration:
                self._exhausted = True
        taken = min(wanted, len(self._buffer))
        view[:taken] = self._buffer[:taken]
        del self._buffer[:taken]
        return taken


def reader_over(chunks: Iterator[bytes]) -> IO[bytes]:
    """Wrap a chunk iterator in a buffered binary reader.

    Args:
        chunks: The byte chunks to serve, in order.

    Returns:
        A readable stream over them.
    """
    return io.BufferedReader(IteratorStream(chunks))  # type: ignore[return-value]
