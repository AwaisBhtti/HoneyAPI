from fastapi import FastAPI

from app.api.auth import router as auth_router
from app.db.seed import seed_db
from app.security.errors import register_error_handlers


def create_app() -> FastAPI:
    app = FastAPI(
        title="HoneyAPI",
        description="Deception and Intrusion Telemetry Service",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
    )
    register_error_handlers(app)
    app.include_router(auth_router)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return app


seed_db()
app = create_app()
