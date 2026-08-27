"""
POST /upload/dataset, GET /upload/sources, GET /upload/sources/{id}
---------------------------------------------------------------------
The "bring your own data" feature — lets any company upload their own CSV
of security/network logs, from any source, and get it analyzed by the same
trained models the rest of ThreatLens AI uses. Not limited to the
CICIDS2017 schema: src/ingestion/upload_processor.py aligns whatever
columns the upload has against what the model actually expects, so two
companies with differently-shaped exports can both be analyzed correctly.
"""

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

from src.database.models import Alert, DataSource
from src.database.session import get_db
from src.ingestion.upload_processor import analyze_uploaded_dataset
from src.models.registry import ModelNotTrainedError
from api.schemas.schemas import DataSourceOut, UploadAlertPreview, UploadAnalysisOut

router = APIRouter(prefix="/upload", tags=["upload"])

MAX_UPLOAD_MB = 50


@router.post("/dataset", response_model=UploadAnalysisOut)
async def upload_dataset(
    file: UploadFile = File(...),
    source_name: str = Form(...),
    db: Session = Depends(get_db),
):
    """
    Accepts a CSV upload (e.g. a company's own network/security log export)
    plus a label identifying who/what it's from, runs it through the full
    detection pipeline (anomaly + classification + threat scoring), and
    returns an immediate summary. Only the highest-risk rows are persisted
    as individual Alert rows — the full aggregate summary is stored on the
    DataSource record itself, so uploading a very large file doesn't flood
    the database with millions of low-risk rows.
    """
    if not file.filename.lower().endswith(".csv"):
        raise HTTPException(400, "Only .csv files are supported right now.")

    contents = await file.read()
    if len(contents) > MAX_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(413, f"File too large — max {MAX_UPLOAD_MB} MB.")

    try:
        result = analyze_uploaded_dataset(contents, source_name=source_name)
    except ModelNotTrainedError as e:
        raise HTTPException(503, str(e))
    except Exception as e:
        # Any parsing/analysis failure surfaces as a clear 400 rather than a
        # raw 500 — the most common real cause is a CSV that isn't
        # comma-delimited or has no usable numeric columns at all.
        raise HTTPException(400, f"Could not analyze this file: {e}")

    if result.rows_analyzed == 0:
        raise HTTPException(422, "No valid rows remained after cleaning — check the file's format.")

    ds = DataSource(
        name=source_name,
        original_filename=file.filename,
        total_rows=result.total_rows,
        rows_analyzed=result.rows_analyzed,
        rows_dropped_invalid=result.rows_dropped_invalid,
        avg_threat_score=result.avg_threat_score,
        critical_count=result.critical_count,
        high_count=result.high_count,
        attack_breakdown=result.attack_breakdown,
    )
    db.add(ds)
    db.commit()
    db.refresh(ds)

    for alert_row in result.top_alerts:
        db.add(Alert(
            source_dataset_id=ds.id,
            attack_category=alert_row["attack_category"],
            threat_score=alert_row["threat_score"],
            severity=alert_row["severity"],
            description=f"From uploaded dataset '{source_name}' ({file.filename})",
        ))
    db.commit()

    return UploadAnalysisOut(
        source_id=ds.id,
        source_name=source_name,
        total_rows=result.total_rows,
        rows_analyzed=result.rows_analyzed,
        rows_dropped_invalid=result.rows_dropped_invalid,
        attack_breakdown=result.attack_breakdown,
        avg_threat_score=result.avg_threat_score,
        critical_count=result.critical_count,
        high_count=result.high_count,
        top_alerts=[UploadAlertPreview(**a) for a in result.top_alerts],
    )


@router.get("/sources", response_model=list[DataSourceOut])
def list_sources(db: Session = Depends(get_db)):
    """Lists every dataset uploaded so far — one entry per company/source."""
    return db.query(DataSource).order_by(DataSource.uploaded_at.desc()).all()


@router.get("/sources/{source_id}", response_model=DataSourceOut)
def get_source(source_id: int, db: Session = Depends(get_db)):
    ds = db.query(DataSource).filter(DataSource.id == source_id).first()
    if ds is None:
        raise HTTPException(404, f"Data source {source_id} not found")
    return ds
