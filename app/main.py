from fastapi import FastAPI, Request

from app.api.admin import router as admin_router
from app.api.auth import router as auth_router
from app.api.data import router as data_router
from app.api.decoy import router as decoy_router
from app.api.replay import router as replay_router
from app.config import MAX_BODY_BYTES
from app.db.seed import seed_db
from app.security.errors import error_response, register_error_handlers


def create_app() -> FastAPI:
    app = FastAPI(
        title="HoneyAPI",
        description="Deception and Intrusion Telemetry Service",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
    )
    register_error_handlers(app)

    @app.middleware("http")
    async def body_size_cap(request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > MAX_BODY_BYTES:
            return error_response(413, "PAYLOAD_TOO_LARGE", "Request body exceeds limit")
        return await call_next(request)

    app.include_router(auth_router)
    app.include_router(data_router)
    app.include_router(admin_router)
    app.include_router(replay_router)
    app.include_router(decoy_router)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return app


seed_db()
app = create_app()
