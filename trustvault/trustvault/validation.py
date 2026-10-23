"""Input validation: uploaded files and text fields.

Uploaded files are identified by their content (magic bytes / container structure),
never by the client-supplied MIME type. The extension must agree with the detected
type. Anything that can execute in a browser or an office suite (HTML, SVG, scripts,
macro-enabled Office files, PDFs with JavaScript/launch actions) is refused.
"""
from __future__ import annotations

import io
import re
import unicodedata
import zipfile
from dataclasses import dataclass


class ValidationError(ValueError):
    def __init__(self, message: str, field: str | None = None):
        super().__init__(message)
        self.field = field


@dataclass(frozen=True)
class FileType:
    kind: str
    content_type: str
    extensions: tuple[str, ...]


PDF = FileType("pdf", "application/pdf", (".pdf",))
PNG = FileType("png", "image/png", (".png",))
JPEG = FileType("jpeg", "image/jpeg", (".jpg", ".jpeg"))
DOCX = FileType("docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", (".docx",))
XLSX = FileType("xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", (".xlsx",))
PPTX = FileType("pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation", (".pptx",))
TXT = FileType("txt", "text/plain", (".txt",))
CSV = FileType("csv", "text/csv", (".csv",))
ALLOWED = (PDF, PNG, JPEG, DOCX, XLSX, PPTX, TXT, CSV)
ALLOWED_EXTENSIONS = sorted({e for t in ALLOWED for e in t.extensions})

# Unicode characters that change how a filename *looks* (e.g. "invoice‮fdp.exe"
# renders as "invoiceexe.pdf").
_BIDI = {"‪", "‫", "‬", "‭", "‮", "⁦", "⁧", "⁨", "⁩", "‎", "‏"}
_PDF_ACTIVE = (b"/JavaScript", b"/JS ", b"/JS(", b"/JS<", b"/Launch", b"/EmbeddedFile", b"/RichMedia", b"/XFA")
_MAX_ZIP_ENTRIES = 2000
_MAX_ZIP_RATIO = 200  # declared uncompressed size / compressed size


def clean_text(value, field: str, *, max_len: int, min_len: int = 1, pattern: str | None = None) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{field} is required", field)
    value = unicodedata.normalize("NFKC", value)
    value = "".join(ch for ch in value if ch.isprintable() and ch not in _BIDI).strip()
    value = re.sub(r"\s+", " ", value)
    if len(value) < min_len:
        raise ValidationError(f"{field} is required", field)
    if len(value) > max_len:
        raise ValidationError(f"{field} must be at most {max_len} characters", field)
    if pattern and not re.fullmatch(pattern, value):
        raise ValidationError(f"{field} contains characters that are not allowed", field)
    return value


def clean_title(value) -> str:
    return clean_text(value, "title", max_len=160)


def clean_category(value) -> str:
    return clean_text(value, "category", max_len=60, pattern=r"[\w][\w &/().,-]*")


def clean_filename(value) -> str:
    if not isinstance(value, str) or not value:
        raise ValidationError("file name is missing", "file")
    value = unicodedata.normalize("NFKC", value)
    value = value.replace("\\", "/").split("/")[-1]  # drop any client-side path
    value = "".join(ch for ch in value if ch.isprintable() and ch not in _BIDI)
    value = re.sub(r"[<>:\"|?*\x00]", "_", value).strip(" .")
    if not value or value.startswith("."):
        raise ValidationError("file name is not valid", "file")
    if len(value) > 150:
        stem, dot, ext = value.rpartition(".")
        value = (stem[: 150 - len(ext) - 1] + "." + ext) if dot else value[:150]
    return value


def _detect_zip_office(data: bytes) -> FileType:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        infos = zf.infolist()
    except zipfile.BadZipFile as exc:
        raise ValidationError("file is a damaged Office/ZIP container", "file") from exc
    if len(infos) > _MAX_ZIP_ENTRIES:
        raise ValidationError("Office file has too many parts", "file")
    total_uncompressed = sum(i.file_size for i in infos)
    if total_uncompressed > _MAX_ZIP_RATIO * max(len(data), 1):
        raise ValidationError("Office file has a suspicious compression ratio", "file")
    names = {i.filename for i in infos}
    if any(n.startswith("/") or ".." in n.split("/") for n in names):
        raise ValidationError("Office file contains unsafe paths", "file")
    if "[Content_Types].xml" not in names:
        raise ValidationError("ZIP archives are not accepted; only DOCX, XLSX and PPTX", "file")
    if any(n.lower().endswith("vbaproject.bin") for n in names):
        raise ValidationError("macro-enabled Office files are not accepted", "file")
    if any(n.startswith("word/") for n in names):
        return DOCX
    if any(n.startswith("xl/") for n in names):
        return XLSX
    if any(n.startswith("ppt/") for n in names):
        return PPTX
    raise ValidationError("unrecognised Office document", "file")


def _detect_text(data: bytes, ext: str) -> FileType:
    if b"\x00" in data:
        raise ValidationError("text file contains binary data", "file")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValidationError("text files must be UTF-8", "file") from exc
    head = text[:1024].lstrip().lower()
    if head.startswith(("<!doctype", "<html", "<svg", "<?xml", "<script")):
        raise ValidationError("HTML/SVG/XML content is not accepted", "file")
    return CSV if ext == ".csv" else TXT


def detect_type(data: bytes, filename: str) -> FileType:
    ext = ("." + filename.rsplit(".", 1)[-1].lower()) if "." in filename else ""
    if ext not in ALLOWED_EXTENSIONS:
        raise ValidationError(f"file type not allowed; accepted: {', '.join(ALLOWED_EXTENSIONS)}", "file")
    if data.startswith(b"%PDF-"):
        if any(marker in data for marker in _PDF_ACTIVE):
            raise ValidationError("PDFs with JavaScript, launch actions or embedded files are not accepted", "file")
        detected = PDF
    elif data.startswith(b"\x89PNG\r\n\x1a\n"):
        detected = PNG
    elif data.startswith(b"\xff\xd8\xff"):
        detected = JPEG
    elif data.startswith(b"PK\x03\x04"):
        detected = _detect_zip_office(data)
    elif ext in (".txt", ".csv"):
        detected = _detect_text(data, ext)
    else:
        raise ValidationError("file content does not match any accepted type", "file")
    if ext not in detected.extensions:
        raise ValidationError(f"file extension {ext} does not match its content ({detected.kind})", "file")
    return detected


def validate_upload(data: bytes, filename: str, max_bytes: int) -> tuple[str, FileType]:
    name = clean_filename(filename)
    if len(data) == 0:
        raise ValidationError("file is empty", "file")
    if len(data) > max_bytes:
        raise ValidationError(f"file exceeds {max_bytes // (1024 * 1024)} MB", "file")
    return name, detect_type(data, name)
