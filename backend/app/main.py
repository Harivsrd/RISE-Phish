"""Main entry point for the RISE-Phish FastAPI backend application.
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.app.core.config import get_settings
from backend.app.core.logging import logger
from backend.app.api.routes import router as api_router

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan event handler for startup and shutdown procedures."""
    logger.info(f"Starting {settings.APP_NAME} in '{settings.APP_ENV}' environment.")
    yield
    logger.info(f"Shutting down {settings.APP_NAME}.")


def create_application() -> FastAPI:
    """Factory function to initialize and configure the FastAPI application."""
    application = FastAPI(
        title=settings.APP_NAME,
        description="Cross-Representation Discrepancy-Aware Phishing Detection System",
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan
    )

    # CORS configuration
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register API routes
    application.include_router(api_router, prefix=settings.API_V1_PREFIX)

    return application


app = create_application()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG
    )
