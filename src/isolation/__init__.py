"""
Remote Browser Isolation and Document Sanitization Module
Handles safe interactions with malicious URLs and documents.
"""

from .schemas import (
    RBISessionRequest, 
    RBISessionResponse,
    SanitizationRequest,
    SanitizationResponse
)
from .kasm_client import get_kasm_client
from .dangerzone import get_dangerzone_manager

__all__ = [
    "RBISessionRequest",
    "RBISessionResponse",
    "SanitizationRequest",
    "SanitizationResponse",
    "get_kasm_client",
    "get_dangerzone_manager"
]
