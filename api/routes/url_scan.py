"""
POST /scan/url, GET /scan/history, GET /scan/history/{id}
-----------------------------------------------------------
The "scan a website link" feature -- sits next to the dataset-upload
feature (api/routes/upload.py) on the same "Upload Data" page, but runs
the separate URL heuristic scanner (src/models/url_scanner.py) instead of
the trained CICIDS2017 models, since a URL isn't network-flow data.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from src.database.models import URLScan
from src.database.session import get_db
from src.models.url_scanner import scan_url
from api.schemas.schemas import URLScanIn, URLScanOut

router = APIRouter(prefix="/scan", tags=["url_scan"])


@router.post("/url", response_model=URLScanOut)
def scan_website(payload: URLScanIn, db: Session = Depends(get_db)):
    if not payload.url or not payload.url.strip():
        raise HTTPException(400, "Please provide a URL to scan.")

    result = scan_url(payload.url)

    record = URLScan(
        url=result.url,
        risk_score=result.risk_score,
        severity=result.severity,
        reachable=result.reachable,
        flags=result.flags,
        error=result.error,
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    return record


@router.get("/history", response_model=list[URLScanOut])
def list_scans(limit: int = 50, db: Session = Depends(get_db)):
    return db.query(URLScan).order_by(URLScan.scanned_at.desc()).limit(limit).all()


@router.get("/history/{scan_id}", response_model=URLScanOut)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    record = db.query(URLScan).filter(URLScan.id == scan_id).first()
    if record is None:
        raise HTTPException(404, f"Scan {scan_id} not found")
    return record
