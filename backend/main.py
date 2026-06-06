"""
ThreatLens API — main entry point.

Startup sequence:
  1. Init DB tables
  2. Run MITRE ATT&CK ingestion (if DB empty)
  3. Schedule recurring ingestion jobs
  4. Serve FastAPI app
"""
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

from database import get_db, init_db
from api.routes import router as intel_router
from api.auth import router as auth_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler()


def run_mitre_ingestion():
    from ingestion.mitre import ingest_mitre
    db = next(get_db())
    try:
        ingest_mitre(db)
    finally:
        db.close()


def run_otx_ingestion():
    from ingestion.otx import ingest_otx
    db = next(get_db())
    try:
        ingest_otx(db)
    finally:
        db.close()


def run_blog_parser():
    from ingestion.blog_parser import ingest_blog_feeds
    db = next(get_db())
    try:
        ingest_blog_feeds(db)
    finally:
        db.close()


def run_aging():
    from intelligence.aging import run_aging as _age
    db = next(get_db())
    try:
        _age(db)
    finally:
        db.close()


def run_actor_enrichment():
    """Enrich actors from MISP Galaxy + Malpedia, backfill metadata, then rescore."""
    from ingestion.misp_galaxy import ingest_misp_galaxy
    from ingestion.malpedia import ingest_malpedia
    from intelligence.enrich import enrich_metadata
    from intelligence.confidence import run_corroboration
    db = next(get_db())
    try:
        ingest_misp_galaxy(db)
        ingest_malpedia(db)
        enrich_metadata(db)
        run_corroboration(db)
    finally:
        db.close()


def run_blog_then_corroborate():
    """Ingest IOCs from blogs, then recompute confidence over the new evidence."""
    from ingestion.blog_parser import ingest_blog_feeds
    from intelligence.confidence import run_corroboration
    db = next(get_db())
    try:
        ingest_blog_feeds(db)
        run_corroboration(db)
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup ──────────────────────────────────────────────────────────────
    logger.info("ThreatLens starting up...")
    init_db()

    # Seed MITRE on first run
    from database import SessionLocal
    from models import ThreatActor
    db = SessionLocal()
    actor_count = db.query(ThreatActor).count()
    db.close()

    if actor_count == 0:
        logger.info("Empty DB — seeding MITRE ATT&CK + enrichment sources...")
        run_mitre_ingestion()
        run_actor_enrichment()  # MISP Galaxy + Malpedia + metadata backfill + corroboration
        # IOC ingestion from blogs is slower — run it once in the background
        # (threadpool) so the API starts serving immediately.
        scheduler.add_job(run_blog_then_corroborate, "date", run_date=datetime.now(), id="seed_blogs")

    # Schedule jobs
    # MITRE: weekly (data doesn't change often)
    scheduler.add_job(run_mitre_ingestion, CronTrigger(day_of_week="sun", hour=2), id="mitre")
    # Actor enrichment (MISP/Malpedia/metadata/corroboration): weekly, after MITRE
    scheduler.add_job(run_actor_enrichment, CronTrigger(day_of_week="sun", hour=3), id="enrichment")
    # OTX: every 6 hours
    scheduler.add_job(run_otx_ingestion, CronTrigger(hour="*/6"), id="otx")
    # Blog parser + corroboration: every 12 hours
    scheduler.add_job(run_blog_then_corroborate, CronTrigger(hour="*/12"), id="blogs")
    # Aging: daily at 3am
    scheduler.add_job(run_aging, CronTrigger(hour=3), id="aging")

    scheduler.start()
    logger.info("✓ Scheduler started")

    yield  # app is running

    # ── Shutdown ─────────────────────────────────────────────────────────────
    scheduler.shutdown()
    logger.info("ThreatLens shutdown complete")


app = FastAPI(
    title="ThreatLens API",
    description="Threat Actor Intelligence Platform — IOCs, TTPs, Actor Profiles",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:3000").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error: {exc}", exc_info=True)
    return JSONResponse(status_code=500, content={"error": "internal_error", "message": "An unexpected error occurred."})


# Mount routers
app.include_router(intel_router, prefix="/api/v1")
app.include_router(auth_router, prefix="/api/v1")


@app.get("/")
def root():
    return {
        "service": "ThreatLens API",
        "version": "1.0.0",
        "docs": "/docs",
        "register": "/api/v1/auth/register",
        "status": "operational",
    }


@app.get("/health")
def health():
    return {"status": "ok"}
