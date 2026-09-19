"""FastAPI application entrypoint.

Run from project root:
    uvicorn backend.app:app --reload
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import FileResponse
from pathlib import Path
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.config import get_settings
from backend.database import connect, ping
from routes import audit as audit_routes
from routes import batches as batch_routes
from backend import customers as customer_routes
from routes import discovery as discovery_routes
from routes import marketing as marketing_routes
from routes import policies as policy_routes
from routes import reveal as reveal_routes

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("privacy-shield")


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        connect()
        logger.info("MongoDB connection established")
    except Exception as exc:  # noqa: BLE001
        logger.warning("MongoDB connection failed on startup: %s", exc)
    yield


app = FastAPI(
    title="Privacy-Preserving Customer Data Platform API",
    description="Backend for the Privacy Shield CDP — discovery, protection, gateway, reveal, audit.",
    version="1.0.0",
    lifespan=lifespan,
)

# ----- CORS (local dev only) -----
settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "http://127.0.0.1:8000",
        "http://localhost:8000",
        "http://127.0.0.1:3000",
        "http://localhost:3000",
        "null",  # file:// origin
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ----- Exception handlers (no secrets leak) -----
@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled error: %s", type(exc).__name__)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )


# ----- Routers -----
app.include_router(customer_routes.router)
app.include_router(discovery_routes.router)
app.include_router(policy_routes.router)
app.include_router(batch_routes.router)
app.include_router(marketing_routes.router)
app.include_router(reveal_routes.router)
app.include_router(audit_routes.router)


# ----- Root & health -----
@app.get("/", tags=["meta"])
def root():
    return FileResponse(Path(__file__).resolve().parent.parent / "frontend" / "index.html")
    return {
        "message": "Privacy-Preserving Customer Data Platform API",
        "status": "running",
    }


@app.get("/health", tags=["meta"])
def health():
    ok = ping()
    return {
        "status": "healthy" if ok else "degraded",
        "mongodb": "connected" if ok else "unreachable",
    }



