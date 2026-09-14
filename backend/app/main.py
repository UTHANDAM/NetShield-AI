"""
NetShield AI — Application Entry Point
Network Anomaly Detection & Threat Monitoring System
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
import os

from app.config import settings
from app.database import init_db
from app.routers import auth, traffic, alerts, anomaly, models, reports, incidents, notifications, threat_intel, analytics, platform
from app.services.ml_engine import ml_engine
from app.services.seed_data import seed_database


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""
    print(f"\n{'='*50}")
    print(f"  Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    print(f"{'='*50}\n")

    # 1. Initialize SQLite Database
    await init_db()

    # 2. Load trained ML models
    try:
        ml_engine.load_models()
    except Exception as e:
        print(f"[WARNING] ML model loading failed: {e}")

    # 3. Seed database with initial data (first run only)
    try:
        await seed_database()
    except Exception as e:
        print(f"[WARNING] Database seeding failed: {e}")

    print(f"\n[READY] {settings.APP_NAME} is running!")
    print(f"  API Docs: http://localhost:8000/docs")
    print(f"  Database: {settings.DATABASE_PATH}")
    print(f"  Models:   {settings.ML_MODELS_DIR}\n")

    yield

    print(f"\n{settings.APP_NAME} shutting down.\n")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Network Anomaly Detection & Threat Monitoring System API",
    lifespan=lifespan,
)

# Enable CORS for Next.js frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve reports directory for downloads
reports_dir = settings.REPORTS_DIR
if os.path.exists(reports_dir):
    app.mount("/reports", StaticFiles(directory=reports_dir), name="reports")

# Register Routers — Milestone 1 & 2
app.include_router(auth.router)
app.include_router(traffic.router)
app.include_router(alerts.router)
app.include_router(anomaly.router)
app.include_router(models.router)
app.include_router(reports.router)

# Register Routers — Milestone 3
app.include_router(incidents.router)
app.include_router(notifications.router)
app.include_router(threat_intel.router)
app.include_router(analytics.router)
app.include_router(platform.router)


@app.get("/")
async def root():
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "online",
        "docs_url": "/docs",
    }


@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "database": "sqlite",
        "models_loaded": len(ml_engine.models),
        "preprocessors_loaded": len(ml_engine.preprocessors),
    }
