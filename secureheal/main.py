"""FastAPI application entry point."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from secureheal.config import settings
from secureheal.db.models import Base
from secureheal.db.session import engine

logging.basicConfig(level=getattr(logging, settings.LOG_LEVEL))
logger = logging.getLogger("secureheal")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan — create tables on startup."""
    logger.info("SecureHeal-AI starting up …")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables ready.")
    yield
    logger.info("SecureHeal-AI shutting down.")
    await engine.dispose()


app = FastAPI(
    title="SecureHeal-AI",
    description="Multi-Agent Framework for Security Investigation and Self-Healing",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health():
    """Health-check endpoint."""
    return {"status": "healthy", "version": "0.1.0"}


# Import and register API routers
from secureheal.api.routes import router as api_router  # noqa: E402

app.include_router(api_router)
