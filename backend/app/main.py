import os
import datetime
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.models.database import engine, Base, get_db
from backend.app.models.models import User
from backend.app.core.security import get_password_hash
from backend.app.services.detection import seed_default_rules
from backend.app.services.websocket import manager

# Import routers
from backend.app.api.auth import router as auth_router
from backend.app.api.logs import router as logs_router
from backend.app.api.rules import router as rules_router
from backend.app.api.incidents import router as incidents_router
from backend.app.api.simulation import router as simulation_router
from backend.app.api.soar import router as soar_router

# Initialize Database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="SentinelAI Autonomous AI SOC & Threat Investigation Platform API",
    version="1.0.0"
)

# CORS Configuration - allow access from React frontend dev server / production domains
raw_origins = os.getenv("ALLOWED_ORIGINS", "*")
allowed_origins = [o.strip() for o in raw_origins.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins if allowed_origins else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API Routers
app.include_router(auth_router, prefix=settings.API_V1_STR)
app.include_router(logs_router, prefix=settings.API_V1_STR)
app.include_router(rules_router, prefix=settings.API_V1_STR)
app.include_router(incidents_router, prefix=settings.API_V1_STR)
app.include_router(simulation_router, prefix=settings.API_V1_STR)
app.include_router(soar_router, prefix=settings.API_V1_STR)

@app.on_event("startup")
def startup_event():
    """Startup initialization: seeds default users and detection rules."""
    db = next(get_db())
    try:
        # Seed default users if they don't exist
        admin_exists = db.query(User).filter(User.username == "admin").first()
        if not admin_exists:
            new_admin = User(
                username="admin",
                hashed_password=get_password_hash("admin123"),
                role="admin",
                is_active=True
            )
            db.add(new_admin)
            
        analyst_exists = db.query(User).filter(User.username == "analyst").first()
        if not analyst_exists:
            new_analyst = User(
                username="analyst",
                hashed_password=get_password_hash("analyst123"),
                role="analyst",
                is_active=True
            )
            db.add(new_analyst)
            
        db.commit()
        
        # Seed default detection rules
        seed_default_rules(db)
        
        print("SentinelAI startup checks completed successfully. Seeded default configurations.")
    except Exception as e:
        db.rollback()
        print(f"Error during startup initialization: {e}")
    finally:
        db.close()

# Real-Time WebSocket Interface
@app.websocket("/api/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time alerts and log updates broadcast.
    """
    await manager.connect(websocket)
    try:
        # Keep connection open.
        while True:
            # We don't expect messages from client for now, just keep connection alive
            _ = await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        print(f"WebSocket client connection error: {e}")
        manager.disconnect(websocket)

@app.get("/")
def read_root():
    """Root endpoint returning service status."""
    return {
        "status": "online",
        "platform": settings.PROJECT_NAME,
        "api_docs": "/docs",
        "version": "1.0.0"
    }

@app.get("/health")
@app.get("/api/health")
@app.get("/ping")
@app.get("/api/ping")
def health_check():
    """Health check webhook endpoint for cron job / uptime ping monitors (e.g. cron-job.org / UptimeRobot)."""
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }

@app.get("/api/ai/status")
def get_ai_status():
    """Returns AI provider connection state and active model."""
    has_key = bool(settings.OPENROUTER_API_KEY)
    return {
        "provider": settings.AI_PROVIDER,
        "model": settings.AI_MODEL,
        "ai_enabled": has_key,
        "detection_source": "cloud_ai" if has_key else "local_engine"
    }
