"""
Demo Mode Configuration
Centralized feature flags for the graduation presentation.
Ensures reliable, fast, and reproducible demonstrations.
"""

import os

class DemoConfig:
    # Use abstract simulated clients instead of live APIs
    ENABLE_SIMULATORS = os.getenv("DEMO_ENABLE_SIMULATORS", "true").lower() == "true"
    
    # Pre-populate the database with good/bad samples
    PRELOAD_DEMO_SAMPLES = os.getenv("DEMO_PRELOAD_SAMPLES", "true").lower() == "true"
    
    # Pre-render analysis reports to avoid waiting 10 minutes per sample
    AUTO_GENERATE_REPORTS = os.getenv("DEMO_AUTO_REPORTS", "true").lower() == "true"
    
    # Redact sensitive IP addresses or API keys in the dashboard output
    HIDE_SENSITIVE_LOGS = os.getenv("DEMO_HIDE_SENSITIVE", "true").lower() == "true"
    
    # Mock evasion behavior for the presentation
    SIMULATE_EVASION_ATTEMPTS = True

    @classmethod
    def apply(cls, app=None):
        """Applies these settings to the global application state."""
        import logging
        logger = logging.getLogger(__name__)
        logger.info("🎓 Initializing Sandbox Platform in Demo/Graduation Mode")
        
        if cls.ENABLE_SIMULATORS:
            logger.info("--> Using Simulated Backends (Kasm, E2B, DRAKVUF)")
            
        if cls.HIDE_SENSITIVE_LOGS:
            logger.info("--> Sensitive log redaction enabled")

if __name__ == "__main__":
    # Test the config loading
    logging.basicConfig(level=logging.INFO)
    DemoConfig.apply()
