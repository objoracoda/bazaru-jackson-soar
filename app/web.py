
import os
import secrets
from pathlib import Path

import requests
from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from app.services.ai import (
    AIAnalysisError,
    analyze_incident,
    build_event_context,
)
from app.services.database import (
    add_incident_comment,
    get_incident,
    get_incident_history,
    get_incident_report,
    get_incidents,
    save_alerts,
    save_incident_report,
    update_incident_status,
)
from app.services.wazuh import WazuhClient


router = APIRouter()

templates = Jinja2Templates(
    directory=Path(__file__).resolve().parent / "templates"
)

STATUSES = {"new", "in_progress", "closed"}


def authorized(request: Request):
    return request.session.get("logged_in") is True


def check_csrf(request: Request, csrf_token: str):
    expected = request.session.get("csrf_token", "")

    if not expected or not secrets.compare_digest(
        csrf_token, expected
    ):
        raise HTTPException(
            status_code=403,
            detail="Invalid CSRF token",
        )


def load_raw_event(incident):
    """
    Загружает исходный JSON конкретного алерта
    из Wazuh Indexer.

    Используется и для предпросмотра,
    и для AI-анализа.
    """
    try:
        raw_event = WazuhClient().get_alert_document(
            incident["wazuh_index"],
            incident["wazuh_id"],
        )

        if raw_event is None:
            return (
                None,
                "Исходное событие не найдено в Wazuh Indexer.",
            )

        return raw_event, None

    except (requests.RequestException, ValueError, KeyError):
        return (
            None,
            "Не удалось получить исходное событие Wazuh.",
        )


def render_incident_page(
    request,
    incident_id,
    ai_result=None,
    ai_error=None,
    incident=None,
    raw_event=None,
    wazuh_error=None,
    raw_loaded=False,
):
    if incident is None:
        incident = get_incident(incident_id)

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    if not raw_loaded:
        raw_event, wazuh_error = load_raw_event(incident)

    report = get_incident_report(incident_id)

    ai_context = build_event_context(
        incident,
        raw_event,
    )

    return templates.TemplateResponse(
        request,
        "incident.html",
        {
            "incident": incident,
            "report": report,
            "raw_event": raw_event,
            "wazuh_error": wazuh_error,
            "history": get_incident_history(incident_id),
            "csrf_token": request.session["csrf_token"],
            "ai_context": ai_context,
            "ai_result": ai_result,
            "ai_error": ai_error,
        },
    )


@router.get("/login")
def login_page(request: Request):
    if authorized(request):
        return RedirectResponse(
            "/panel",
            status_code=303,
        )

    return templates.TemplateResponse(
        request,
        "login.html",
        {"error": False},
    )


@router.post("/login")
def login(
    request: Request,
    password: str = Form(...),
):
    expected = os.environ["SOAR_WEB_PASSWORD"]

    if not secrets.compare_digest(password, expected):
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": True},
            status_code=401,
        )

    request.session.clear()
    request.session["logged_in"] = True
    request.session["csrf_token"] = secrets.token_urlsafe(32)

    return RedirectResponse(
        "/panel",
        status_code=303,
    )


@router.get("/panel")
def dashboard(
    request: Request,
    status: str = "",
    q: str = "",
    notice: str = "",
):
    if not authorized(request):
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    all_alerts = get_incidents(limit=100)

    counts = {
        "total": len(all_alerts),
        "new": sum(
            a["status"] == "new"
            for a in all_alerts
        ),
        "in_progress": sum(
            a["status"] == "in_progress"
            for a in all_alerts
        ),
        "closed": sum(
            a["status"] == "closed"
            for a in all_alerts
        ),
    }

    alerts = all_alerts

    if status in STATUSES:
        alerts = [
            a for a in alerts
            if a["status"] == status
        ]

    if q:
        search = q.casefold()

        alerts = [
            a for a in alerts
            if search in " ".join([
                str(a.get("agent") or ""),
                str(a.get("description") or ""),
                str(a.get("rule_id") or ""),
            ]).casefold()
        ]

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "alerts": alerts,
            "counts": counts,
            "status_filter": status,
            "search": q,
            "notice": notice,
            "csrf_token": request.session["csrf_token"],
        },
    )


@router.post("/panel/sync")
def sync_from_panel(
    request: Request,
    csrf_token: str = Form(...),
):
    if not authorized(request):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized",
        )

    check_csrf(request, csrf_token)

    try:
        result = WazuhClient().get_alerts(
            min_level=7,
            limit=100,
        )
        added = save_alerts(result["alerts"])

    except (requests.RequestException, ValueError, KeyError):
        return RedirectResponse(
            "/panel?notice=sync_error",
            status_code=303,
        )

    return RedirectResponse(
        f"/panel?notice=imported_{added}",
        status_code=303,
    )


@router.post("/panel/incidents/{incident_id}/status")
def update_status_from_panel(
    request: Request,
    incident_id: int,
    status: str = Form(...),
    csrf_token: str = Form(...),
):
    if not authorized(request):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized",
        )

    check_csrf(request, csrf_token)

    if status not in STATUSES:
        raise HTTPException(
            status_code=400,
            detail="Invalid status",
        )

    if not update_incident_status(incident_id, status):
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    return RedirectResponse(
        "/panel?notice=updated",
        status_code=303,
    )


@router.post("/logout")
def logout(
    request: Request,
    csrf_token: str = Form(...),
):
    if not authorized(request):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized",
        )

    check_csrf(request, csrf_token)
    request.session.clear()

    return RedirectResponse(
        "/login",
        status_code=303,
    )


@router.get("/panel/incidents/{incident_id}")
def incident_detail(
    request: Request,
    incident_id: int,
):
    if not authorized(request):
        return RedirectResponse(
            "/login",
            status_code=303,
        )

    return render_incident_page(
        request,
        incident_id,
    )


@router.post("/panel/incidents/{incident_id}/comment")
def create_incident_comment(
    request: Request,
    incident_id: int,
    comment: str = Form(...),
    csrf_token: str = Form(...),
):
    if not authorized(request):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized",
        )

    check_csrf(request, csrf_token)

    try:
        saved = add_incident_comment(
            incident_id,
            comment,
        )
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Comment must contain 1-2000 characters",
        )

    if not saved:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    return RedirectResponse(
        f"/panel/incidents/{incident_id}",
        status_code=303,
    )


@router.post("/panel/incidents/{incident_id}/set-status")
def set_incident_status_from_detail(
    request: Request,
    incident_id: int,
    status: str = Form(...),
    csrf_token: str = Form(...),
):
    if not authorized(request):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized",
        )

    check_csrf(request, csrf_token)

    if status not in STATUSES:
        raise HTTPException(
            status_code=400,
            detail="Invalid status",
        )

    if not update_incident_status(incident_id, status):
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    return RedirectResponse(
        f"/panel/incidents/{incident_id}",
        status_code=303,
    )


@router.post("/panel/incidents/{incident_id}/report")
def save_report_from_panel(
    request: Request,
    incident_id: int,
    description: str = Form(""),
    investigation: str = Form(""),
    verdict: str = Form("undetermined"),
    conclusion: str = Form(""),
    csrf_token: str = Form(...),
):
    if not authorized(request):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized",
        )

    check_csrf(request, csrf_token)

    try:
        saved = save_incident_report(
            incident_id=incident_id,
            description=description,
            investigation=investigation,
            verdict=verdict,
            conclusion=conclusion,
        )
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid incident report",
        )

    if not saved:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    return RedirectResponse(
        f"/panel/incidents/{incident_id}?saved=1",
        status_code=303,
    )


@router.post("/panel/incidents/{incident_id}/ai-analyze")
def analyze_incident_from_panel(
    request: Request,
    incident_id: int,
    csrf_token: str = Form(...),
    consent: str = Form(""),
):
    if not authorized(request):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized",
        )

    check_csrf(request, csrf_token)

    if consent != "yes":
        raise HTTPException(
            status_code=400,
            detail="AI analysis requires consent",
        )

    incident = get_incident(incident_id)

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    raw_event, wazuh_error = load_raw_event(incident)

    if raw_event is None:
        return render_incident_page(
            request,
            incident_id,
            ai_error=(
                "Расширенный анализ недоступен: "
                + (wazuh_error or "нет исходного события")
            ),
            incident=incident,
            raw_event=None,
            wazuh_error=wazuh_error,
            raw_loaded=True,
        )

    try:
        result = analyze_incident(
            incident,
            raw_event,
        )

        return render_incident_page(
            request,
            incident_id,
            ai_result=result,
            incident=incident,
            raw_event=raw_event,
            raw_loaded=True,
        )

    except AIAnalysisError as exc:
        return render_incident_page(
            request,
            incident_id,
            ai_error=str(exc),
            incident=incident,
            raw_event=raw_event,
            raw_loaded=True,
        )

