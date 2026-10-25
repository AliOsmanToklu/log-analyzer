"""HTTP layer: routes, request validation and wiring. Logic lives in `service`."""

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from contextlib import asynccontextmanager
from typing import Annotated, Any, Literal

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    FastAPI,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
)
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from .. import __version__
from ..models import Detection, Severity
from ..parsers import detect_format
from . import service
from .db import make_engine, make_session_factory
from .orm import AnalysisRecord, AnalysisStatus
from .schemas import AnalysisDetail, AnalysisSummary, FindingHit, Health, Page
from .settings import Settings

# Room for the multipart framing around the file itself
MULTIPART_OVERHEAD = 64 * 1024
MAX_FILENAME = 255

DESCRIPTION = """
Upload SSH auth logs or Windows logon CSV exports and get back brute force,
post-brute-force login and slow scan findings.

Analyses run in the background: `POST /analyses` answers `202 Accepted` right away,
then poll `GET /analyses/{id}` until `status` is `completed` or `failed`.
Uploaded logs are not stored, only the findings.
"""


def get_settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def get_sessions(request: Request) -> sessionmaker[Session]:
    sessions: sessionmaker[Session] = request.app.state.sessions
    return sessions


def get_session(
    sessions: Annotated[sessionmaker[Session], Depends(get_sessions)],
) -> Iterator[Session]:
    with sessions() as session:
        yield session


SettingsDep = Annotated[Settings, Depends(get_settings)]
SessionsDep = Annotated[sessionmaker[Session], Depends(get_sessions)]
SessionDep = Annotated[Session, Depends(get_session)]
Limit = Annotated[int, Query(ge=1, le=100, description="Page size")]
Offset = Annotated[int, Query(ge=0, description="Items to skip")]

NOT_FOUND: dict[int | str, dict[str, Any]] = {404: {"description": "No analysis with this id"}}

router = APIRouter()


def too_large(settings: Settings) -> str:
    return f"upload is larger than the {settings.max_upload_bytes} byte limit"


def clean_filename(name: str | None) -> str:
    """Drop any client-side directories and keep the name within the column size."""
    base = (name or "").replace("\\", "/").rsplit("/", 1)[-1]
    return base[:MAX_FILENAME] or "upload"


def find_analysis(session: Session, analysis_id: uuid.UUID) -> AnalysisRecord:
    record = service.get_analysis(session, analysis_id)
    if record is None:
        raise HTTPException(404, "analysis not found")
    return record


@router.post(
    "/analyses",
    status_code=202,
    tags=["analyses"],
    summary="Upload a log for analysis",
    responses={413: {"description": "Upload too large"}},
)
def create_analysis(
    response: Response,
    background: BackgroundTasks,
    session: SessionDep,
    sessions: SessionsDep,
    settings: SettingsDep,
    file: Annotated[UploadFile, File(description="SSH auth log or Windows logon CSV export")],
    fmt: Annotated[
        Literal["auto", "ssh", "windows"],
        Form(alias="format", description="auto: .csv is a Windows export, anything else SSH"),
    ] = "auto",
    threshold: Annotated[int, Form(ge=1)] = 10,
    window_seconds: Annotated[int, Form(ge=1)] = 60,
    scan_threshold: Annotated[int, Form(ge=1)] = 3,
    year: Annotated[
        int | None, Form(ge=1970, le=9999, description="Year for classic syslog timestamps")
    ] = None,
) -> AnalysisSummary:
    data = file.file.read(settings.max_upload_bytes + 1)
    if len(data) > settings.max_upload_bytes:
        raise HTTPException(413, too_large(settings))

    filename = clean_filename(file.filename)
    record = service.create_analysis(
        session,
        filename=filename,
        fmt=detect_format(filename) if fmt == "auto" else fmt,
        threshold=threshold,
        window_seconds=window_seconds,
        scan_threshold=scan_threshold,
        year=year,
    )
    lines = data.decode("utf-8-sig", errors="replace").splitlines(keepends=True)
    background.add_task(service.run_analysis, sessions, record.id, lines)

    response.headers["Location"] = f"/analyses/{record.id}"
    return AnalysisSummary.from_record(record)


@router.get("/analyses", tags=["analyses"], summary="List analyses, newest first")
def list_analyses(
    session: SessionDep,
    limit: Limit = 20,
    offset: Offset = 0,
    status: AnalysisStatus | None = None,
) -> Page[AnalysisSummary]:
    records, total = service.list_analyses(session, limit=limit, offset=offset, status=status)
    return Page(
        items=[AnalysisSummary.from_record(r) for r in records],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/analyses/{analysis_id}",
    tags=["analyses"],
    summary="Get an analysis with all its findings",
    responses=NOT_FOUND,
)
def get_analysis(analysis_id: uuid.UUID, session: SessionDep) -> AnalysisDetail:
    return AnalysisDetail.from_record(find_analysis(session, analysis_id))


@router.delete(
    "/analyses/{analysis_id}",
    status_code=204,
    tags=["analyses"],
    summary="Delete an analysis and its findings",
    responses=NOT_FOUND,
)
def delete_analysis(analysis_id: uuid.UUID, session: SessionDep) -> None:
    if not service.delete_analysis(session, analysis_id):
        raise HTTPException(404, "analysis not found")


@router.get("/findings", tags=["findings"], summary="Search findings across all analyses")
def search_findings(
    session: SessionDep,
    ip: str | None = None,
    severity: Severity | None = None,
    detection: Detection | None = None,
    limit: Limit = 20,
    offset: Offset = 0,
) -> Page[FindingHit]:
    rows, total = service.search_findings(
        session, ip=ip, severity=severity, detection=detection, limit=limit, offset=offset
    )
    return Page(
        items=[
            FindingHit(
                ip=finding.ip,
                detection=Detection(finding.detection),
                severity=Severity(finding.severity),
                details=finding.details,
                analysis_id=analysis.id,
                filename=analysis.filename,
                analyzed_at=analysis.created_at,
            )
            for finding, analysis in rows
        ],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/health",
    tags=["meta"],
    summary="Liveness and database check",
    responses={503: {"model": Health, "description": "Database unreachable"}},
)
def health(response: Response, session: SessionDep) -> Health:
    try:
        session.execute(text("SELECT 1"))
    except SQLAlchemyError:
        response.status_code = 503
        return Health(status="unavailable", database="unreachable")
    return Health(status="ok", database="ok")


@router.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse("/docs")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the application. The database must already be migrated (see `db.upgrade`)."""
    settings = settings or Settings.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        engine = make_engine(settings.database_url)
        app.state.sessions = make_session_factory(engine)
        yield
        engine.dispose()

    app = FastAPI(
        title="log-analyzer",
        version=__version__,
        description=DESCRIPTION,
        lifespan=lifespan,
    )
    app.state.settings = settings

    @app.middleware("http")
    async def reject_oversized_uploads(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        # Refuse early, before the multipart body is spooled to disk
        length = request.headers.get("content-length", "")
        if length.isdigit() and int(length) > settings.max_upload_bytes + MULTIPART_OVERHEAD:
            return JSONResponse({"detail": too_large(settings)}, status_code=413)
        return await call_next(request)

    app.include_router(router)
    return app
