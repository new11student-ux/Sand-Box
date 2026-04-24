"""
Advanced Features Module
Includes DRAKVUF integration, Cowrie honeypot parser, and MITRE ATT&CK tagging.
"""

from .schemas import (
    DrakvufAnalysisJob,
    DrakvufIntrospectionReport,
    CowrieEvent,
    ParsedHoneypotEvent,
    MitreTagResult
)
from .drakvuf_client import get_drakvuf_client
from .cowrie_parser import CowrieParser
from .mitre_tagger import MitreTagger

__all__ = [
    "DrakvufAnalysisJob",
    "DrakvufIntrospectionReport",
    "CowrieEvent",
    "ParsedHoneypotEvent",
    "MitreTagResult",
    "get_drakvuf_client",
    "CowrieParser",
    "MitreTagger"
]
