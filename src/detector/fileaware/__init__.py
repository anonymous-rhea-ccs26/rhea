import os
from .handlers.ooxml import OOXMLHandler
from .handlers.zip import ZipContainerHandler
from .handlers.jpeg import JPEGHandler
from .handlers.png import PNGHandler
from .handlers.pdf import PDFHandler
from .handlers.text import TextHandler
from .handlers.mp3 import MP3Handler
from .handlers.mp4 import MP4Handler
from .handlers.generic import GenericHandler

def _ext_of(path: str) -> str:
    ext = os.path.splitext(path)[1]
    return ext[1:].lower() if ext.startswith(".") else ext.lower()

# REGISTER INSTANCES, generic LAST
_HANDLERS = [
    OOXMLHandler(),
    ZipContainerHandler(),
    JPEGHandler(),
    PNGHandler(),
    PDFHandler(),
    MP3Handler(),
    MP4Handler(),
    TextHandler(),
    GenericHandler(),   # fallback
]

def pick_handler(path: str, magic: bytes | None):
    ext = _ext_of(path)
    mg  = magic or b""
    for h in _HANDLERS:
        try:
            if h.supports(ext, mg):   # instance method
                return h              # return instance
        except Exception:
            continue
    return GenericHandler()            # belt-and-suspenders fallback
