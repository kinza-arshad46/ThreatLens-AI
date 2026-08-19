# ThreatLens AI — API service image (blueprint Section 12: Docker Compose
# for local full-stack startup).
#
# Builds a container that runs the FastAPI backend. The dashboard frontend
# (index.html/style.css/script.js) is a separate static site and is served
# by its own lightweight container in docker-compose.yml — kept apart from
# this image so the Python backend stays small and the frontend can be
# deployed independently (e.g. to Vercel) without needing this image at all.

FROM python:3.11-slim

WORKDIR /app

# System deps needed by some ML libraries (xgboost, shap) at build time.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY api/ ./api/

# Data and model directories are mounted as volumes in docker-compose.yml
# rather than baked into the image, since trained models and datasets
# change independently of the application code.
RUN mkdir -p data/processed models/anomaly models/classifier models/shap

EXPOSE 8000

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
