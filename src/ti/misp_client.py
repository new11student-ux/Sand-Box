"""
Advanced Cybersecurity Sandbox Platform
MISP Threat Intelligence Client

Full integration with MISP for:
- Pre-analysis enrichment (query before detonation)
- Post-analysis IOC push (automated sharing)
- Event creation and management
- Feed synchronization
"""

import os
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field

import httpx
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MISP_URL = os.getenv("MISP_URL", "http://localhost:8081")
MISP_API_KEY = os.getenv("MISP_API_KEY", "")
MISP_VERIFY_SSL = os.getenv("MISP_VERIFY_SSL", "false").lower() == "true"

IOC_TYPE_MAP = {
    "ip": "ip-dst", "domain": "domain", "url": "url",
    "email": "email-src", "file_hash": "sha256", "mutex": "mutex",
    "registry_key": "regkey", "file_path": "filename",
    "user_agent": "user-agent", "filename": "filename",
    "filepath": "filename", "certificate": "x509-fingerprint-sha256",
}

CATEGORY_MAP = {
    "ip-dst": "Network activity", "domain": "Network activity",
    "url": "Network activity", "email-src": "Payload delivery",
    "sha256": "Payload delivery", "md5": "Payload delivery",
    "mutex": "Artifacts dropped", "regkey": "Persistence mechanism",
    "filename": "Payload delivery", "user-agent": "Network activity",
}


class MISPClient:
    """Client for MISP threat intelligence platform integration."""

    def __init__(self, url=None, api_key=None, verify_ssl=None):
        self.url = (url or MISP_URL).rstrip("/")
        self.api_key = api_key or MISP_API_KEY
        self.verify_ssl = verify_ssl if verify_ssl is not None else MISP_VERIFY_SSL
        self._client: Optional[httpx.AsyncClient] = None

        if not self.api_key:
            logger.warning("MISP_API_KEY not configured")

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.url, verify=self.verify_ssl, timeout=30.0,
                headers={
                    "Authorization": self.api_key,
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
            )
        return self._client

    async def _request(self, method, path, **kwargs) -> Optional[Dict]:
        if not self.api_key:
            return None
        client = await self._get_client()
        try:
            resp = await client.request(method, path, **kwargs)
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            logger.error("MISP %s %s error: %s", method, path, exc)
            return None

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def health_check(self) -> bool:
        data = await self._request("GET", "/servers/getVersion")
        if data:
            logger.info("MISP connected — version %s", data.get("version", "?"))
            return True
        return False

    # --- Pre-analysis enrichment ---

    async def enrich_hash(self, hash_value: str) -> Dict[str, Any]:
        """Query MISP for existing intelligence on a file hash."""
        result = {"found": False, "events": [], "tags": [], "threat_level": None}
        for hash_type in ("sha256", "sha1", "md5"):
            data = await self._request("POST", "/attributes/restSearch",
                json={"value": hash_value, "type": hash_type, "limit": 10, "includeEventTags": True})
            if not data:
                continue
            attrs = data.get("response", {}).get("Attribute", [])
            if not attrs:
                continue
            result["found"] = True
            for attr in attrs:
                evt = attr.get("Event", {})
                result["events"].append({
                    "event_id": evt.get("id"), "info": evt.get("info", ""),
                    "threat_level_id": evt.get("threat_level_id"),
                })
                for tag in attr.get("Tag", []):
                    t = tag.get("name", "")
                    if t and t not in result["tags"]:
                        result["tags"].append(t)
                tl = evt.get("threat_level_id")
                if tl:
                    tl = int(tl)
                    if result["threat_level"] is None or tl < result["threat_level"]:
                        result["threat_level"] = tl
            break
        return result

    async def enrich_ioc(self, ioc_type: str, ioc_value: str) -> Dict[str, Any]:
        """Query MISP for a single IOC."""
        misp_type = IOC_TYPE_MAP.get(ioc_type, ioc_type)
        data = await self._request("POST", "/attributes/restSearch",
            json={"value": ioc_value, "type": misp_type, "limit": 5, "includeEventTags": True})
        result = {"found": False, "event_count": 0, "tags": []}
        if not data:
            return result
        attrs = data.get("response", {}).get("Attribute", [])
        if attrs:
            result["found"] = True
            result["event_count"] = len(attrs)
            for attr in attrs:
                for tag in attr.get("Tag", []):
                    t = tag.get("name", "")
                    if t and t not in result["tags"]:
                        result["tags"].append(t)
        return result

    # --- Post-analysis event creation ---

    async def create_event_from_analysis(
        self, sample_sha256, sample_name, verdict, confidence, iocs, behaviors,
        mitre_tactics=None
    ) -> Optional[str]:
        """Create a MISP event from completed sandbox analysis. Returns event UUID."""
        tl_map = {"malicious": 1, "suspicious": 2, "benign": 4, "unknown": 4}
        event_body = {"Event": {
            "info": f"Sandbox analysis: {sample_name} ({verdict})",
            "threat_level_id": tl_map.get(verdict, 4),
            "analysis": 2, "distribution": 0,
            "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "Tag": [
                {"name": f"sandbox:verdict={verdict}"},
                {"name": f"sandbox:confidence={confidence:.2f}"},
                {"name": "tlp:amber" if verdict == "malicious" else "tlp:green"},
            ],
            "Attribute": [
                {"type": "sha256", "category": "Payload delivery",
                 "value": sample_sha256, "to_ids": True,
                 "comment": f"Analyzed sample: {sample_name}"},
                {"type": "filename", "category": "Payload delivery",
                 "value": sample_name, "to_ids": False, "comment": "Original filename"},
            ],
        }}
        if mitre_tactics:
            for t in mitre_tactics:
                event_body["Event"]["Tag"].append({"name": f"mitre-attack:{t}"})
        for ioc in iocs:
            mt = IOC_TYPE_MAP.get(ioc["ioc_type"], ioc["ioc_type"])
            cat = CATEGORY_MAP.get(mt, "Other")
            event_body["Event"]["Attribute"].append({
                "type": mt, "category": cat, "value": ioc["value"],
                "to_ids": True, "comment": f"Extracted IOC ({ioc.get('confidence','medium')})",
            })
        data = await self._request("POST", "/events/add", json=event_body)
        if data:
            uuid = data.get("Event", {}).get("uuid")
            logger.info("Created MISP event uuid=%s for %s", uuid, sample_sha256[:16])
            return uuid
        return None

    async def push_iocs(self, event_id, iocs) -> int:
        """Push a batch of IOCs to an existing MISP event."""
        added = 0
        for ioc in iocs:
            mt = IOC_TYPE_MAP.get(ioc["ioc_type"], ioc["ioc_type"])
            cat = CATEGORY_MAP.get(mt, "Other")
            result = await self._request("POST", f"/attributes/add/{event_id}",
                json={"Attribute": {"type": mt, "category": cat,
                      "value": ioc["value"], "to_ids": True, "distribution": 0}})
            if result:
                added += 1
        logger.info("Pushed %d/%d IOCs to MISP event %s", added, len(iocs), event_id)
        return added

    async def pull_recent_iocs(self, hours=24, limit=500) -> List[Dict]:
        """Pull recently-added IOCs from MISP."""
        ts = int(datetime.now(timezone.utc).timestamp() - hours * 3600)
        data = await self._request("POST", "/attributes/restSearch",
            json={"timestamp": str(ts), "limit": limit, "to_ids": True,
                  "enforceWarninglist": True, "includeEventTags": True})
        if not data:
            return []
        attrs = data.get("response", {}).get("Attribute", [])
        results = []
        for a in attrs:
            results.append({
                "type": a.get("type"), "value": a.get("value"),
                "event_id": a.get("event_id"),
                "tags": [t.get("name", "") for t in a.get("Tag", [])],
            })
        logger.info("Pulled %d recent IOCs from MISP", len(results))
        return results

    async def correlate_sample(self, sha256: str) -> Dict[str, Any]:
        """Full correlation for a sample hash against MISP."""
        correlation = {"direct_match": False, "related_events": [],
                       "campaigns": [], "threat_actors": [], "priority_boost": 0}
        enrichment = await self.enrich_hash(sha256)
        if not enrichment["found"]:
            return correlation
        correlation["direct_match"] = True
        correlation["related_events"] = enrichment["events"]
        if enrichment["threat_level"]:
            correlation["priority_boost"] = max(0, 4 - enrichment["threat_level"])
        for tag in enrichment["tags"]:
            tl = tag.lower()
            if "campaign:" in tl or "apt" in tl:
                correlation["campaigns"].append(tag)
            if "threat-actor:" in tl:
                correlation["threat_actors"].append(tag)
        return correlation
