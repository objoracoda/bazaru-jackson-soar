
import os
import secrets
from pathlib import Path

import requests
from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from app.services.database import (
    get_incidents,
    save_alerts,
    update_incident_status,
)
from app.services.wazuh import WazuhClient

from app.services.database import (
    get_incident,
    get_incident_history,
    add_incident_comment,
)

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
        raise HTTPException(status_code=403, detail="Invalid CSRF token")


@router.get("/login")
def login_page(request: Request):
    if authorized(request):
        return RedirectResponse("/panel", status_code=303)

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

    return RedirectResponse("/panel", status_code=303)


@router.get("/panel")
def dashboard(
    request: Request,
    status: str = "",
    q: str = "",
    notice: str = "",
):
    if not authorized(request):
        return RedirectResponse("/login", status_code=303)

    # Пока используем последние 100 сохранённых записей.
    all_alerts = get_incidents(limit=100)

    counts = {
        "total": len(all_alerts),
        "new": sum(a["status"] == "new" for a in all_alerts),
        "in_progress": sum(
            a["status"] == "in_progress" for a in all_alerts
        ),
        "closed": sum(a["status"] == "closed" for a in all_alerts),
    }

    alerts = all_alerts

    if status in STATUSES:
        alerts = [a for a in alerts if a["status"] == status]

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
        raise HTTPException(status_code=401, detail="Unauthorized")

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
        raise HTTPException(status_code=401, detail="Unauthorized")

    check_csrf(request, csrf_token)

    if status not in STATUSES:
        raise HTTPException(status_code=400, detail="Invalid status")

    updated = update_incident_status(incident_id, status)

    if not updated:
        raise HTTPException(status_code=404, detail="Not found")

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
        raise HTTPException(status_code=401, detail="Unauthorized")

    check_csrf(request, csrf_token)
    request.session.clear()

    return RedirectResponse("/login", status_code=303)


@router.get("/panel/incidents/{incident_id}")
def incident_detail(request: Request, incident_id: int):
    if not authorized(request):
        return RedirectResponse("/login", status_code=303)

    incident = get_incident(incident_id)

    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    raw_event = None
    wazuh_error = None

    try:
        raw_event = WazuhClient().get_alert_document(
            incident["wazuh_index"],
            incident["wazuh_id"],
        )

        if raw_event is None:
            wazuh_error = "Документ больше не найден в Wazuh Indexer."

    except (requests.RequestException, ValueError):
        wazuh_error = "Не удалось получить исходное событие Wazuh."

    return templates.TemplateResponse(
        request,
        "incident.html",
        {
            "incident": incident,
            "raw_event": raw_event,
            "wazuh_error": wazuh_error,
            "history": get_incident_history(incident_id),
            "csrf_token": request.session["csrf_token"],
        },
    )


@router.post("/panel/incidents/{incident_id}/comment")
def create_incident_comment(
    request: Request,
    incident_id: int,
    comment: str = Form(...),
    csrf_token: str = Form(...),
):
    if not authorized(request):
        raise HTTPException(status_code=401, detail="Unauthorized")

    check_csrf(request, csrf_token)

    try:
        saved = add_incident_comment(incident_id, comment)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Comment must contain 1-2000 characters",
        )

    if not saved:
        raise HTTPException(status_code=404, detail="Incident not found")

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
        raise HTTPException(status_code=401, detail="Unauthorized")

    check_csrf(request, csrf_token)

    if status not in STATUSES:
        raise HTTPException(status_code=400, detail="Invalid status")

    if not update_incident_status(incident_id, status):
        raise HTTPException(status_code=404, detail="Not found")

    return RedirectResponse(
        f"/panel/incidents/{incident_id}",
        status_code=303,
    )
