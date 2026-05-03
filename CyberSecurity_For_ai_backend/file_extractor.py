# ─── File & Image Text Extractor for AI Firewall ─────────────────────
# Extracts text content from uploaded files and images so the security
# layer can scan them for prompt injection attacks.
#
# Supported formats:
#   Images : png, jpg, jpeg, gif, bmp, webp  (OCR via pytesseract)
#   Docs   : txt, md, csv, pdf, docx, eml, msg

import os
import io
import csv
import email
import logging

logger = logging.getLogger(__name__)

# ─── Supported extensions ─────────────────────────────────────────────
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"}
TEXT_EXTENSIONS = {".txt", ".md", ".csv"}
DOC_EXTENSIONS = {".pdf", ".docx", ".eml", ".msg"}
ALL_EXTENSIONS = IMAGE_EXTENSIONS | TEXT_EXTENSIONS | DOC_EXTENSIONS


def is_supported(filename: str) -> bool:
    """Check if the file extension is supported."""
    ext = os.path.splitext(filename)[1].lower()
    return ext in ALL_EXTENSIONS


def extract_text(file_bytes: bytes, filename: str) -> str:
    """
    Extract text from the given file bytes based on its extension.
    Returns the extracted text string.
    Raises ValueError for unsupported formats.
    """
    ext = os.path.splitext(filename)[1].lower()

    if ext in IMAGE_EXTENSIONS:
        return _extract_from_image(file_bytes)
    elif ext in {".txt", ".md"}:
        return _extract_from_text(file_bytes)
    elif ext == ".csv":
        return _extract_from_csv(file_bytes)
    elif ext == ".pdf":
        return _extract_from_pdf(file_bytes)
    elif ext == ".docx":
        return _extract_from_docx(file_bytes)
    elif ext == ".eml":
        return _extract_from_eml(file_bytes)
    elif ext == ".msg":
        return _extract_from_msg(file_bytes)
    else:
        raise ValueError(f"Unsupported file format: {ext}")


# ═════════════════════════════════════════════════════════════════════
# Individual extractors
# ═════════════════════════════════════════════════════════════════════

def _extract_from_image(file_bytes: bytes) -> str:
    """OCR an image using pytesseract."""
    try:
        from PIL import Image
        import pytesseract

        image = Image.open(io.BytesIO(file_bytes))
        text = pytesseract.image_to_string(image)
        return text.strip()
    except ImportError:
        raise RuntimeError("pytesseract or Pillow is not installed. Run: pip install pytesseract pillow")
    except Exception as e:
        # If tesseract binary is missing, give a clear message
        if "tesseract is not installed" in str(e).lower() or "not found" in str(e).lower():
            raise RuntimeError(
                "Tesseract OCR is not installed on the system. "
                "Install it with: sudo apt install tesseract-ocr"
            )
        raise RuntimeError(f"OCR failed: {e}")


def _extract_from_text(file_bytes: bytes) -> str:
    """Read plain text / markdown files."""
    try:
        return file_bytes.decode("utf-8").strip()
    except UnicodeDecodeError:
        return file_bytes.decode("latin-1").strip()


def _extract_from_csv(file_bytes: bytes) -> str:
    """Read CSV and concatenate all cell values."""
    try:
        text = file_bytes.decode("utf-8")
    except UnicodeDecodeError:
        text = file_bytes.decode("latin-1")

    reader = csv.reader(io.StringIO(text))
    rows = []
    for row in reader:
        rows.append(" ".join(row))
    return "\n".join(rows).strip()


def _extract_from_pdf(file_bytes: bytes) -> str:
    """Extract text from a PDF using pdfplumber."""
    try:
        import pdfplumber
    except ImportError:
        raise RuntimeError("pdfplumber is not installed. Run: pip install pdfplumber")

    text_parts = []
    with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
        for page in pdf.pages:
            page_text = page.extract_text()
            if page_text:
                text_parts.append(page_text)
    return "\n".join(text_parts).strip()


def _extract_from_docx(file_bytes: bytes) -> str:
    """Extract text from a Word .docx file."""
    try:
        from docx import Document
    except ImportError:
        raise RuntimeError("python-docx is not installed. Run: pip install python-docx")

    doc = Document(io.BytesIO(file_bytes))
    paragraphs = [p.text for p in doc.paragraphs if p.text.strip()]
    return "\n".join(paragraphs).strip()


def _extract_from_eml(file_bytes: bytes) -> str:
    """Extract text from an .eml email file."""
    try:
        text = file_bytes.decode("utf-8")
    except UnicodeDecodeError:
        text = file_bytes.decode("latin-1")

    msg = email.message_from_string(text)
    parts = []

    # Add subject
    subject = msg.get("Subject", "")
    if subject:
        parts.append(f"Subject: {subject}")

    # Walk the MIME parts and extract text
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    try:
                        parts.append(payload.decode("utf-8"))
                    except UnicodeDecodeError:
                        parts.append(payload.decode("latin-1"))
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            try:
                parts.append(payload.decode("utf-8"))
            except UnicodeDecodeError:
                parts.append(payload.decode("latin-1"))

    return "\n".join(parts).strip()


def _extract_from_msg(file_bytes: bytes) -> str:
    """Extract text from an Outlook .msg file."""
    try:
        import extract_msg
    except ImportError:
        raise RuntimeError("extract-msg is not installed. Run: pip install extract-msg")

    import tempfile
    # extract-msg needs a file path, so write to a temp file
    with tempfile.NamedTemporaryFile(suffix=".msg", delete=False) as tmp:
        tmp.write(file_bytes)
        tmp_path = tmp.name

    try:
        msg = extract_msg.Message(tmp_path)
        parts = []
        if msg.subject:
            parts.append(f"Subject: {msg.subject}")
        if msg.body:
            parts.append(msg.body)
        msg.close()
        return "\n".join(parts).strip()
    finally:
        os.unlink(tmp_path)
