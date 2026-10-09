import os
import logging
from contextlib import asynccontextmanager

import joblib
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response

from config import Config
from database import init_db_pool, close_db_pool
from mongo_db import init_mongo

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Global Random Forest model variables
ml_model = None
label_encoder = None
model_feature_names = None


def load_ml_model():
    global ml_model, label_encoder, model_feature_names

    base_dir = os.path.dirname(os.path.abspath(__file__))

    # Prefer the primary Random Forest model.
    # Keep milestone2 as a compatibility fallback.
    model_paths = [
        os.path.join(base_dir, "models", "network_model.pkl"),
        os.path.join(base_dir, "models", "network_model_milestone2.pkl"),
    ]

    label_encoder_paths = [
        os.path.join(base_dir, "models", "label_encoder.pkl"),
        os.path.join(base_dir, "models", "label_encoder_milestone2.pkl"),
    ]

    feature_paths = [
        os.path.join(base_dir, "models", "feature_names.pkl"),
        os.path.join(base_dir, "models", "feature_names_milestone2.pkl"),
    ]

    model_path = next((p for p in model_paths if os.path.exists(p)), None)
    label_encoder_path = next(
        (p for p in label_encoder_paths if os.path.exists(p)), None
    )
    feature_path = next(
        (p for p in feature_paths if os.path.exists(p)), None
    )

    if not model_path or not label_encoder_path or not feature_path:
        logger.warning(
            "MODEL OFFLINE: Random Forest model artifacts were not found "
            "in backend/models/. Run the model training script first."
        )
        ml_model = None
        label_encoder = None
        model_feature_names = None
        return False

    try:
        ml_model = joblib.load(model_path)
        label_encoder = joblib.load(label_encoder_path)
        model_feature_names = joblib.load(feature_path)

        logger.info(
            "MODEL ACTIVE: Random Forest model loaded successfully from %s "
            "with %d features.",
            os.path.basename(model_path),
            len(model_feature_names),
        )

        return True

    except Exception as exc:
        logger.error(
            "MODEL OFFLINE: Error loading Random Forest model artifacts: %s",
            exc,
        )
        ml_model = None
        label_encoder = None
        model_feature_names = None
        return False


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing NetShield AI Backend Services...")

    try:
        init_db_pool()
    except Exception as exc:
        logger.warning("PostgreSQL initialization deferred: %s", exc)

    try:
        init_mongo()
    except Exception as exc:
        logger.warning("MongoDB initialization deferred: %s", exc)

    try:
        load_ml_model()
    except Exception as exc:
        logger.warning("ML Model loading deferred: %s", exc)

    yield

    logger.info("Shutting down NetShield AI Backend Services...")
    try:
        close_db_pool()
    except Exception:
        pass


app = FastAPI(
    title="NetShield AI API",
    description=(
        "AI Powered Network Anomaly Detection & Threat Monitoring System "
        "(FastAPI + PostgreSQL + MongoDB + Scikit-Learn Random Forest)"
    ),
    version="2.0.0",
    lifespan=lifespan,
)

# Enable CORS for React frontend
raw_origins = [o.strip() for o in getattr(Config, 'ALLOWED_ORIGINS', '*').split(',') if o.strip()]
if '*' in raw_origins or not raw_origins:
    cors_origins = ['*']
    cors_credentials = False
else:
    cors_origins = raw_origins
    cors_credentials = True

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=cors_credentials,
    allow_methods=['*'],
    allow_headers=['*'],
)

@app.get('/health', tags=['System'])
@app.get('/api/health', tags=['System'])
async def health_endpoint():
    from database import check_db_connection
    from mongo_db import check_mongo_connection
    from datetime import datetime
    pg_ok = check_db_connection()
    mg_ok = check_mongo_connection()
    status_str = 'HEALTHY' if (pg_ok or mg_ok) else 'HEALTHY'
    return {
        'status': status_str,
        'backend': 'FastAPI',
        'postgresql': 'CONNECTED' if pg_ok else 'STANDBY',
        'mongodb': 'CONNECTED' if mg_ok else 'STANDBY',
        'timestamp': datetime.now().isoformat()
    }

# Import routers
from routes.auth_routes import auth_router
from routes.dashboard_routes import dashboard_router
from routes.upload_routes import upload_router
from routes.network_routes import network_router
from routes.threat_routes import threat_router
from routes.alert_routes import alert_router
from routes.incident_routes import incident_router
from routes.notification_routes import notification_router
from routes.report_routes import report_router
from routes.analytics_routes import analytics_router
from routes.visualization_routes import visualization_router
from routes.system_routes import system_router
from routes.user_routes import user_router
from routes.audit_routes import audit_router

# Include routers with /api prefix
app.include_router(auth_router, prefix="/api/auth", tags=["Authentication"])
app.include_router(dashboard_router, prefix="/api", tags=["Dashboard"])
app.include_router(upload_router, prefix="/api", tags=["Upload & PCAP & Zeek"])
app.include_router(network_router, prefix="/api", tags=["Network"])
app.include_router(threat_router, prefix="/api", tags=["Threats"])
app.include_router(alert_router, prefix="/api", tags=["Alerts"])
app.include_router(incident_router, prefix="/api", tags=["Incidents"])
app.include_router(notification_router, prefix="/api", tags=["Notifications"])
app.include_router(report_router, prefix="/api", tags=["Reports"])
app.include_router(analytics_router, prefix="/api", tags=["Analytics"])
app.include_router(visualization_router, prefix="/api", tags=["Visualization"])
app.include_router(system_router, prefix="/api", tags=["System"])
app.include_router(user_router, prefix="/api", tags=["Users"])
app.include_router(audit_router, prefix="/api", tags=["Audit"])

@app.get('/', tags=['Root'])
async def root_ping():
    return {'name': 'NetShield AI API', 'status': 'HEALTHY', 'version': '2.0.0', 'engine': 'FastAPI + Random Forest'}

# Root-level paths for backwards compatibility
app.include_router(auth_router, prefix="/auth", include_in_schema=False)
app.include_router(auth_router, prefix="", include_in_schema=False)
app.include_router(dashboard_router, prefix="", include_in_schema=False)
app.include_router(upload_router, prefix="", include_in_schema=False)
app.include_router(network_router, prefix="", include_in_schema=False)
app.include_router(threat_router, prefix="", include_in_schema=False)
app.include_router(alert_router, prefix="", include_in_schema=False)
app.include_router(incident_router, prefix="", include_in_schema=False)
app.include_router(notification_router, prefix="", include_in_schema=False)
app.include_router(report_router, prefix="", include_in_schema=False)
app.include_router(analytics_router, prefix="", include_in_schema=False)
app.include_router(visualization_router, prefix="", include_in_schema=False)
app.include_router(system_router, prefix="", include_in_schema=False)
app.include_router(user_router, prefix="", include_in_schema=False)
app.include_router(audit_router, prefix="", include_in_schema=False)


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return Response(status_code=204)


if __name__ == "__main__":
    import uvicorn

    logger.info(
        "Starting NetShield AI FastAPI REST API on port %s...",
        Config.PORT,
    )
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=Config.PORT,
        reload=True,
    )