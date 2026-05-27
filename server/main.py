"""FastAPI server application entry point."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_fastapi_instrumentator import Instrumentator
from slowapi import _rate_limit_exceeded_handler

from server.database import init_db
from server.logger import logger
from server.config import get_settings
from server.ratelimit import limiter
from server.api import router

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("=" * 60)
    logger.info("MiniEDR Server starting up")
    logger.info(f"Database: {settings.DATABASE_URL}")
    logger.info(f"VT enrichment: {'enabled' if settings.VT_ENABLED else 'disabled'}")
    logger.info(f"Authentication: {'required' if settings.AUTH_TOKEN else 'disabled'}")
    logger.info(f"CORS origins: {settings.CORS_ORIGINS}")

    init_db()
    logger.info("Database initialized")
    logger.info("=" * 60)

    yield

    logger.info("MiniEDR Server shutting down")


app = FastAPI(
    title="MiniEDR Server",
    description="Central event collection and analysis server",
    version="1.0.0",
    lifespan=lifespan,
)

# Prometheus metrics — auto-instrumentation
# Exposes /metrics with default HTTP metrics (request count, duration, etc.)
# plus custom EDR metrics defined in server.metrics
Instrumentator().instrument(app).expose(app)

# CORS middleware — restrict origins in production via CORS_ORIGINS env var
# In development, keep "*" (all origins). In production, set a comma-separated
# list of allowed origins (e.g. "https://app.example.com,https://admin.example.com").
_cors_origins = settings.CORS_ORIGINS.strip()
if _cors_origins == "*":
    allow_origins = ["*"]
else:
    allow_origins = [o.strip() for o in _cors_origins.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.state.limiter = limiter
app.add_exception_handler(429, _rate_limit_exceeded_handler)

# Include routes
app.include_router(router)


if __name__ == "__main__":
    import uvicorn

    logger.info(f"Starting server on {settings.SERVER_HOST}:{settings.SERVER_PORT}")
    uvicorn.run(
        "server.main:app",
        host=settings.SERVER_HOST,
        port=settings.SERVER_PORT,
        workers=settings.WORKERS,
        log_level=settings.LOG_LEVEL.lower(),
    )
