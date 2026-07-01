"""Cloud storage discovery (S3 / GCS / Azure Blob) — §3.7.

App code and configs routinely name the buckets they use. Origami reads those
bodies anyway (JS, HTML, configs); this **recognizes the references** (free,
on-host) and — under `--buckets` — **probes each bucket's listing endpoint** (a
read-only GET) to flag the publicly-listable ones and enumerate a sample of the
objects they expose. Pure helpers here; the scanner fold does the fetching.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class BucketRef:
    provider: str            # "s3" | "gcs" | "azure"
    name: str                # bucket / container
    account: str = ""        # azure storage account

    @property
    def label(self) -> str:
        acct = f"{self.account}/" if self.account else ""
        return f"{self.provider}:{acct}{self.name}"


# A bucket/container name shape (conservative — avoids matching region strings).
_NAME = r"[a-z0-9][a-z0-9._\-]{1,61}[a-z0-9]"
_S3_VHOST = re.compile(rf"({_NAME})\.s3[.\-][a-z0-9.\-]*amazonaws\.com", re.I)
# path-style only: `s3` must NOT be preceded by a hostname label (that's vhost —
# what follows the '/' there is an object key, not a bucket).
_S3_PATH = re.compile(rf"(?<![\w.\-])s3[.\-][a-z0-9.\-]*amazonaws\.com/({_NAME})", re.I)
_S3_URI = re.compile(rf"s3://({_NAME})", re.I)
_GCS_VHOST = re.compile(rf"({_NAME})\.storage\.googleapis\.com", re.I)
_GCS_PATH = re.compile(rf"(?<![\w.\-])storage\.googleapis\.com/({_NAME})", re.I)
_GCS_URI = re.compile(rf"gs://({_NAME})", re.I)
_AZURE = re.compile(rf"([a-z0-9]{{3,24}})\.blob\.core\.windows\.net/({_NAME})", re.I)

# Provider infrastructure labels that are never a real bucket name.
_NOISE = frozenset({"s3", "www", "storage", "blob", "amazonaws", "googleapis"})


def find_bucket_refs(body: bytes) -> set[BucketRef]:
    """Every S3/GCS/Azure bucket reference in a response body (host or config)."""
    if not body:
        return set()
    text = body.decode("latin-1", "replace")
    out: set[BucketRef] = set()
    for rx in (_S3_VHOST, _S3_PATH, _S3_URI):
        for m in rx.findall(text):
            n = m.lower()
            if n not in _NOISE:
                out.add(BucketRef("s3", n))
    for rx in (_GCS_VHOST, _GCS_PATH, _GCS_URI):
        for m in rx.findall(text):
            n = m.lower()
            if n not in _NOISE:
                out.add(BucketRef("gcs", n))
    for acct, cont in _AZURE.findall(text):
        out.add(BucketRef("azure", cont.lower(), acct.lower()))
    return out


def public_url(ref: BucketRef) -> str:
    """The bucket's base URL (used as the finding URL)."""
    if ref.provider == "s3":
        return f"https://{ref.name}.s3.amazonaws.com/"
    if ref.provider == "gcs":
        return f"https://storage.googleapis.com/{ref.name}/"
    if ref.provider == "azure":
        return f"https://{ref.account}.blob.core.windows.net/{ref.name}/"
    return ""


def list_url(ref: BucketRef) -> str:
    """The read-only listing endpoint for this bucket/container."""
    if ref.provider == "s3":
        return f"https://{ref.name}.s3.amazonaws.com/?list-type=2"
    if ref.provider == "gcs":
        return f"https://storage.googleapis.com/{ref.name}"
    if ref.provider == "azure":
        return (f"https://{ref.account}.blob.core.windows.net/{ref.name}"
                "?restype=container&comp=list")
    return ""


def is_listable(status: int, body: bytes) -> bool:
    """True when a listing response is a public object index (not AccessDenied)."""
    if status != 200 or not body:
        return False
    head = body[:1024]
    return (b"<ListBucketResult" in head or b"<EnumerationResults" in head
            or b"<Contents>" in body[:8192])


_KEY = re.compile(rb"<(?:Key|Name)>([^<]+)</(?:Key|Name)>", re.I)


def parse_keys(body: bytes, limit: int = 20) -> list[str]:
    """Object keys from an S3/GCS/Azure listing XML (`<Key>`/`<Name>`)."""
    out, seen = [], set()
    for m in _KEY.findall(body or b""):
        k = m.decode("utf-8", "replace")
        if k and k not in seen:
            seen.add(k)
            out.append(k)
        if len(out) >= limit:
            break
    return out
