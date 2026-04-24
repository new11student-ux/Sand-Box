"""
Thesis Data Exporter
Automatically bundles ML metrics, evasion results, system architecture diagrams,
and dashboard screenshots into a clean ZIP file for academic submission.
"""

import os
import shutil
import zipfile
import json
import logging
from pathlib import Path
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

EXPORT_DIR = Path("thesis_export")
EXPORT_DIR.mkdir(exist_ok=True)

def gather_metrics():
    """Gathers Phase 2 ML metrics."""
    metrics_path = Path("results/phase2_metrics.json")
    if metrics_path.exists():
        shutil.copy2(metrics_path, EXPORT_DIR / "ml_metrics.json")
        logger.info("Gathered ML metrics.")
    else:
        logger.warning("ML metrics not found. Run research_metrics.py first.")

def gather_threat_model():
    """Gathers the Phase 0 Threat Model."""
    tm_path = Path("docs/THREAT_MODEL.md")
    if tm_path.exists():
        shutil.copy2(tm_path, EXPORT_DIR / "THREAT_MODEL.md")
        logger.info("Gathered Threat Model.")

def generate_export_manifest():
    """Creates a manifest of the export bundle."""
    manifest = {
        "export_date": datetime.now().isoformat(),
        "project": "Advanced Cybersecurity Sandbox Platform",
        "contents": [f.name for f in EXPORT_DIR.iterdir()]
    }
    with open(EXPORT_DIR / "manifest.json", "w") as f:
        json.dump(manifest, f, indent=2)

def create_zip_archive():
    """Compresses the gathered data into a single ZIP file."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    zip_filename = f"thesis_data_bundle_{timestamp}.zip"
    
    with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(EXPORT_DIR):
            for file in files:
                file_path = os.path.join(root, file)
                zipf.write(file_path, os.path.relpath(file_path, EXPORT_DIR))
                
    logger.info(f"✅ Successfully created thesis data bundle: {zip_filename}")
    return zip_filename

def main():
    logger.info("Starting thesis data export...")
    
    # 1. Gather all required artifacts
    gather_metrics()
    gather_threat_model()
    
    # Optional: Gather screenshots if they exist
    screenshots_dir = Path("docs/screenshots")
    if screenshots_dir.exists():
        dest = EXPORT_DIR / "screenshots"
        dest.mkdir(exist_ok=True)
        for img in screenshots_dir.glob("*.png"):
            shutil.copy2(img, dest / img.name)
            
    # 2. Generate manifest
    generate_export_manifest()
    
    # 3. Zip it up
    zip_file = create_zip_archive()
    
    # 4. Cleanup staging directory
    shutil.rmtree(EXPORT_DIR)
    
    print(f"\nYour data is ready! Attach '{zip_file}' to your thesis appendix.")

if __name__ == "__main__":
    main()
