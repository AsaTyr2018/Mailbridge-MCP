from __future__ import annotations

import base64
from datetime import datetime, timezone
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Any
from xml.etree import ElementTree

from .audit import audit
from .db import db
from .mailops import get_account
from .security import secret_box


DAV_NS = {"d": "DAV:", "card": "urn:ietf:params:xml:ns:carddav", "cal": "urn:ietf:params:xml:ns:caldav"}


@dataclass
class HttpResult:
    status: int
    headers: dict[str, str]
    body: bytes


def _auth_header(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


def _http_request(method: str, url: str, *, username: str, password: str, body: bytes = b"", headers: dict[str, str] | None = None, timeout: int = 30) -> HttpResult:
    request_headers = {
        "User-Agent": "Mailbridge-Sync/0.1",
        "Authorization": _auth_header(username, password),
    }
    request_headers.update(headers or {})
    req = urllib.request.Request(url, data=body if body else None, headers=request_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as response:
            return HttpResult(response.status, dict(response.headers), response.read())
    except urllib.error.HTTPError as exc:
        return HttpResult(exc.code, dict(exc.headers), exc.read())


def _http_request_follow_redirects(method: str, url: str, *, username: str, password: str, body: bytes = b"", headers: dict[str, str] | None = None, timeout: int = 30, max_redirects: int = 5) -> HttpResult:
    current_url = url
    for _ in range(max_redirects + 1):
        response = _http_request(method, current_url, username=username, password=password, body=body, headers=headers, timeout=timeout)
        if response.status not in {301, 302, 303, 307, 308}:
            return response
        location = _header_value(response.headers, "Location")
        if not location:
            return response
        current_url = urllib.parse.urljoin(current_url, location)
    return response


def _dav_put(profile: dict[str, Any], url: str, body: str, content_type: str) -> HttpResult:
    return _http_request(
        "PUT",
        url,
        username=profile["username"],
        password=profile["password"],
        body=body.encode("utf-8"),
        headers={"Content-Type": content_type},
    )


def _dav_delete(profile: dict[str, Any], url: str) -> HttpResult:
    return _http_request("DELETE", url, username=profile["username"], password=profile["password"])


def _profile_row(profile_id: int, user: dict[str, Any] | None = None) -> dict[str, Any]:
    with db() as conn:
        if user and not user.get("is_admin"):
            row = conn.execute(
                """
                SELECT sp.*
                FROM sync_profiles sp
                JOIN accounts a ON a.id = sp.account_id
                WHERE sp.id = ? AND a.owner_user_id = ?
                """,
                (profile_id, user["id"]),
            ).fetchone()
        else:
            row = conn.execute("SELECT * FROM sync_profiles WHERE id = ?", (profile_id,)).fetchone()
    if not row:
        raise ValueError("sync profile not found")
    return dict(row)


def get_sync_profile(profile_id: int, user: dict[str, Any] | None = None) -> dict[str, Any]:
    profile = _profile_row(profile_id, user=user)
    profile.pop("secret", None)
    profile["enabled"] = bool(profile["enabled"])
    return profile


def list_sync_profiles(account_id: int, user: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    account = get_account(account_id, user=user)
    if not account:
        raise ValueError("account not found")
    with db() as conn:
        rows = conn.execute("SELECT * FROM sync_profiles WHERE account_id = ? ORDER BY kind, provider, name", (account_id,)).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        item.pop("secret", None)
        item["enabled"] = bool(item["enabled"])
        result.append(item)
    return result


def create_sync_profile(account_id: int, data: dict[str, Any], user: dict[str, Any] | None = None) -> int:
    account = get_account(account_id, user=user)
    if not account:
        raise ValueError("account not found")
    provider = data["provider"].strip().lower()
    kind = data["kind"].strip().lower()
    if provider not in {"activesync", "carddav", "caldav"}:
        raise ValueError("unsupported provider")
    if kind not in {"contacts", "calendar"}:
        raise ValueError("unsupported sync kind")
    if provider == "carddav" and kind != "contacts":
        raise ValueError("CardDAV only supports contacts")
    if provider == "caldav" and kind != "calendar":
        raise ValueError("CalDAV only supports calendar")
    with db() as conn:
        cur = conn.execute(
            """
            INSERT INTO sync_profiles (
                account_id, kind, provider, name, base_url, username, secret, enabled
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                account_id,
                kind,
                provider,
                data.get("name", "").strip() or f"{provider}-{kind}",
                data.get("base_url", "").strip(),
                data.get("username", "").strip(),
                secret_box.encrypt(data.get("password", "")),
                int(data.get("enabled", True)),
            ),
        )
        profile_id = int(cur.lastrowid)
    audit(actor_type="human", actor_id=str(user["id"] if user else "admin"), interface="http", action="sync_profile_create", status="ok", account_id=account_id, target_resource=str(profile_id))
    return profile_id


def autodiscover_sync_profiles(account_id: int, user: dict[str, Any] | None = None) -> dict[str, Any]:
    account = get_account(account_id, include_secret=True, user=user)
    if not account:
        raise ValueError("account not found")
    discovered: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []
    for candidate in _autodiscovery_candidates(account):
        if _sync_profile_exists(account_id, candidate["provider"], candidate["kind"], candidate["base_url"]):
            skipped.append({**candidate, "reason": "already exists"})
            continue
        test_profile = {
            **candidate,
            "id": 0,
            "account_id": account_id,
            "username": account["imap_username"],
            "password": account["imap_password"],
        }
        test_result = _test_candidate_profile(test_profile)
        if not test_result.get("ok"):
            failed.append({**candidate, "test": test_result})
            continue
        profile_id = create_sync_profile(
            account_id,
            {
                **candidate,
                "username": "",
                "password": "",
                "enabled": True,
            },
            user=user,
        )
        discovered.append({**candidate, "id": profile_id, "test": test_result})
    audit(
        actor_type="human",
        actor_id=str(user["id"] if user else "admin"),
        interface="http",
        action="sync_profile_autodiscover",
        status="ok",
        account_id=account_id,
    )
    return {
        "ok": True,
        "account_id": account_id,
        "created": discovered,
        "skipped": skipped,
        "failed": failed,
    }


def delete_sync_profile(profile_id: int, user: dict[str, Any] | None = None) -> None:
    profile = _profile_row(profile_id, user=user)
    with db() as conn:
        conn.execute("DELETE FROM sync_profiles WHERE id = ?", (profile_id,))
    audit(actor_type="human", actor_id=str(user["id"] if user else "admin"), interface="http", action="sync_profile_delete", status="ok", account_id=int(profile["account_id"]), target_resource=str(profile_id))


def create_contact(account_id: int, data: dict[str, Any], user: dict[str, Any] | None = None, profile_id: int | None = None) -> dict[str, Any]:
    _ensure_contact_allowed(account_id, user=user)
    profile = _writable_profile(account_id, "contacts", user=user, profile_id=profile_id)
    uid = _resource_uid(data.get("uid"), ".vcf")
    vcard = _build_vcard(
        uid=uid,
        display_name=str(data.get("display_name") or data.get("name") or "").strip(),
        email=str(data.get("email") or data.get("emails") or "").strip(),
        phone=str(data.get("phone") or data.get("phones") or "").strip(),
        company=str(data.get("company") or "").strip(),
    )
    url = _profile_resource_url(profile, uid)
    response = _dav_put(profile, url, vcard, "text/vcard; charset=utf-8")
    if response.status not in {200, 201, 204}:
        raise ValueError(f"contact create failed: {response.status}")
    contact = _parse_vcard(vcard)
    _upsert_contact(profile, contact, contact.get("uid") or uid)
    audit(actor_type="mcp_client", actor_id=str(user["id"] if user else "codex"), interface="mcp", action="create_contact", status="ok", account_id=account_id, target_resource=uid)
    return {"ok": True, "account_id": account_id, "profile_id": profile["id"], "uid": uid, "url": url, "contact": contact}


def update_contact(contact_id: int, data: dict[str, Any], user: dict[str, Any] | None = None) -> dict[str, Any]:
    row = _contact_row(contact_id, user=user)
    _ensure_contact_allowed(int(row["account_id"]), user=user)
    profile = _profile_with_secret(int(row["profile_id"]), user=user)
    profile = _writable_provider_profile(profile)
    raw = row["raw_vcard"] or ""
    current = _parse_vcard(raw) if raw else {}
    uid = str(row["provider_uid"])
    contact = {
        "uid": uid,
        "display_name": str(data.get("display_name") or data.get("name") or current.get("display_name") or row["display_name"] or "").strip(),
        "emails": str(data.get("email") or data.get("emails") or current.get("emails") or row["emails"] or "").strip(),
        "phones": str(data.get("phone") or data.get("phones") or current.get("phones") or row["phones"] or "").strip(),
        "company": str(data.get("company") if data.get("company") is not None else current.get("company") or row["company"] or "").strip(),
    }
    vcard = _build_vcard(uid=uid, display_name=contact["display_name"], email=contact["emails"], phone=contact["phones"], company=contact["company"])
    url = _profile_resource_url(profile, uid)
    response = _dav_put(profile, url, vcard, "text/vcard; charset=utf-8")
    if response.status not in {200, 201, 204}:
        raise ValueError(f"contact update failed: {response.status}")
    parsed = _parse_vcard(vcard)
    _upsert_contact(profile, parsed, parsed.get("uid") or uid)
    audit(actor_type="mcp_client", actor_id=str(user["id"] if user else "codex"), interface="mcp", action="update_contact", status="ok", account_id=int(row["account_id"]), target_resource=str(contact_id))
    return {"ok": True, "contact_id": contact_id, "account_id": int(row["account_id"]), "profile_id": profile["id"], "uid": uid, "url": url, "contact": parsed}


def delete_contact(contact_id: int, user: dict[str, Any] | None = None) -> dict[str, Any]:
    row = _contact_row(contact_id, user=user)
    _ensure_contact_allowed(int(row["account_id"]), user=user)
    profile = _profile_with_secret(int(row["profile_id"]), user=user)
    profile = _writable_provider_profile(profile)
    url = _profile_resource_url(profile, str(row["provider_uid"]))
    response = _dav_delete(profile, url)
    if response.status not in {200, 204, 404}:
        raise ValueError(f"contact delete failed: {response.status}")
    with db() as conn:
        conn.execute("DELETE FROM contacts WHERE id = ?", (contact_id,))
    audit(actor_type="mcp_client", actor_id=str(user["id"] if user else "codex"), interface="mcp", action="delete_contact", status="ok", account_id=int(row["account_id"]), target_resource=str(contact_id))
    return {"ok": True, "contact_id": contact_id, "account_id": int(row["account_id"]), "status": response.status}


def create_calendar_event(account_id: int, data: dict[str, Any], user: dict[str, Any] | None = None, profile_id: int | None = None) -> dict[str, Any]:
    _ensure_calendar_allowed(account_id, user=user)
    profile = _writable_profile(account_id, "calendar", user=user, profile_id=profile_id)
    uid = _resource_uid(data.get("uid"), "")
    ics = _build_ics_event(
        uid=uid,
        title=str(data.get("title") or data.get("summary") or "").strip(),
        starts_at=str(data.get("starts_at") or data.get("start") or "").strip(),
        ends_at=str(data.get("ends_at") or data.get("end") or "").strip(),
        location=str(data.get("location") or "").strip(),
        description=str(data.get("description") or "").strip(),
        attendees=str(data.get("attendees") or "").strip(),
    )
    url = _profile_resource_url(profile, uid, extension=".ics")
    response = _dav_put(profile, url, ics, "text/calendar; charset=utf-8")
    if response.status not in {200, 201, 204}:
        raise ValueError(f"calendar event create failed: {response.status}")
    event = _parse_ics_event(ics)
    _upsert_calendar_event(profile, event, event.get("uid") or uid)
    audit(actor_type="mcp_client", actor_id=str(user["id"] if user else "codex"), interface="mcp", action="create_calendar_event", status="ok", account_id=account_id, target_resource=uid)
    return {"ok": True, "account_id": account_id, "profile_id": profile["id"], "uid": uid, "url": url, "event": event}


def update_calendar_event(event_id: int, data: dict[str, Any], user: dict[str, Any] | None = None) -> dict[str, Any]:
    row = _event_row(event_id, user=user)
    _ensure_calendar_allowed(int(row["account_id"]), user=user)
    profile = _profile_with_secret(int(row["profile_id"]), user=user)
    profile = _writable_provider_profile(profile)
    raw = row["raw_ics"] or ""
    current = _parse_ics_event(raw) if raw else {}
    uid = str(row["provider_uid"])
    ics = _build_ics_event(
        uid=uid,
        title=str(data.get("title") or data.get("summary") or current.get("title") or row["title"] or "").strip(),
        starts_at=str(data.get("starts_at") or data.get("start") or current.get("starts_at") or row["starts_at"] or "").strip(),
        ends_at=str(data.get("ends_at") or data.get("end") or current.get("ends_at") or row["ends_at"] or "").strip(),
        location=str(data.get("location") if data.get("location") is not None else current.get("location") or row["location"] or "").strip(),
        description=str(data.get("description") or _ics_value(raw, "DESCRIPTION") or "").strip(),
        attendees=str(data.get("attendees") if data.get("attendees") is not None else current.get("attendees") or row["attendees"] or "").strip(),
    )
    url = _profile_resource_url(profile, uid, extension=".ics")
    response = _dav_put(profile, url, ics, "text/calendar; charset=utf-8")
    if response.status not in {200, 201, 204}:
        raise ValueError(f"calendar event update failed: {response.status}")
    event = _parse_ics_event(ics)
    _upsert_calendar_event(profile, event, event.get("uid") or uid)
    audit(actor_type="mcp_client", actor_id=str(user["id"] if user else "codex"), interface="mcp", action="update_calendar_event", status="ok", account_id=int(row["account_id"]), target_resource=str(event_id))
    return {"ok": True, "event_id": event_id, "account_id": int(row["account_id"]), "profile_id": profile["id"], "uid": uid, "url": url, "event": event}


def delete_calendar_event(event_id: int, user: dict[str, Any] | None = None) -> dict[str, Any]:
    row = _event_row(event_id, user=user)
    _ensure_calendar_allowed(int(row["account_id"]), user=user)
    profile = _profile_with_secret(int(row["profile_id"]), user=user)
    profile = _writable_provider_profile(profile)
    url = _profile_resource_url(profile, str(row["provider_uid"]), extension=".ics")
    response = _dav_delete(profile, url)
    if response.status not in {200, 204, 404}:
        raise ValueError(f"calendar event delete failed: {response.status}")
    with db() as conn:
        conn.execute("DELETE FROM calendar_events WHERE id = ?", (event_id,))
    audit(actor_type="mcp_client", actor_id=str(user["id"] if user else "codex"), interface="mcp", action="delete_calendar_event", status="ok", account_id=int(row["account_id"]), target_resource=str(event_id))
    return {"ok": True, "event_id": event_id, "account_id": int(row["account_id"]), "status": response.status}


def _profile_with_secret(profile_id: int, user: dict[str, Any] | None = None) -> dict[str, Any]:
    profile = _profile_row(profile_id, user=user)
    profile["password"] = secret_box.decrypt(profile.pop("secret"))
    if not profile["username"] or not profile["password"]:
        account = get_account(int(profile["account_id"]), include_secret=True, user=user)
        if account:
            profile["username"] = profile["username"] or account["imap_username"]
            profile["password"] = profile["password"] or account["imap_password"]
    return profile


def test_sync_profile(profile_id: int, user: dict[str, Any] | None = None) -> dict[str, Any]:
    profile = _profile_with_secret(profile_id, user=user)
    provider = profile["provider"]
    if provider == "activesync":
        result = _activesync_options(profile)
    else:
        response = _dav_propfind(profile, depth="0")
        result = {
            "ok": response.status in {200, 207},
            "status": response.status,
            "provider": provider,
            "body_bytes": len(response.body),
        }
    audit(actor_type="human", actor_id=str(user["id"] if user else "admin"), interface="http", action="sync_profile_test", status="ok", account_id=int(profile["account_id"]), target_resource=str(profile_id))
    return result


def discover_sync_profile(profile_id: int, user: dict[str, Any] | None = None) -> dict[str, Any]:
    profile = _profile_with_secret(profile_id, user=user)
    if profile["provider"] == "activesync":
        return _activesync_folders(profile)
    return _dav_discover(profile)


def sync_profile(profile_id: int, user: dict[str, Any] | None = None) -> dict[str, Any]:
    profile = _profile_with_secret(profile_id, user=user)
    try:
        if profile["provider"] == "carddav":
            result = _sync_carddav(profile)
        elif profile["provider"] == "caldav":
            result = _sync_caldav(profile)
        elif profile["provider"] == "activesync":
            result = _sync_activesync(profile)
        else:
            raise ValueError("unsupported provider")
        with db() as conn:
            conn.execute("UPDATE sync_profiles SET last_sync_at = CURRENT_TIMESTAMP, last_sync_error = '', updated_at = CURRENT_TIMESTAMP WHERE id = ?", (profile_id,))
        audit(actor_type="human", actor_id=str(user["id"] if user else "admin"), interface="http", action="sync_profile_sync", status="ok", account_id=int(profile["account_id"]), target_resource=str(profile_id))
        return result
    except Exception as exc:
        with db() as conn:
            conn.execute("UPDATE sync_profiles SET last_sync_error = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (str(exc), profile_id))
        audit(actor_type="human", actor_id=str(user["id"] if user else "admin"), interface="http", action="sync_profile_sync", status="error", account_id=int(profile["account_id"]), target_resource=str(profile_id), error_message=str(exc))
        raise


def _dav_propfind(profile: dict[str, Any], *, depth: str, timeout: int = 30) -> HttpResult:
    body = b'<?xml version="1.0" encoding="utf-8"?><d:propfind xmlns:d="DAV:"><d:prop><d:displayname/><d:getetag/><d:resourcetype/></d:prop></d:propfind>'
    response = _http_request(
        "PROPFIND",
        profile["base_url"],
        username=profile["username"],
        password=profile["password"],
        body=body,
        headers={"Depth": depth, "Content-Type": "application/xml; charset=utf-8"},
        timeout=timeout,
    )
    return response


def _dav_propfind_xml(profile: dict[str, Any], url: str, body: str, *, depth: str) -> HttpResult:
    return _http_request_follow_redirects(
        "PROPFIND",
        url,
        username=profile["username"],
        password=profile["password"],
        body=body.encode("utf-8"),
        headers={"Depth": depth, "Content-Type": "application/xml; charset=utf-8"},
        timeout=5,
    )


def _dav_discover(profile: dict[str, Any]) -> dict[str, Any]:
    response = _dav_propfind(profile, depth="1")
    hrefs = _dav_hrefs(response.body, profile["base_url"]) if response.status in {200, 207} else []
    return {"ok": response.status in {200, 207}, "status": response.status, "collections": hrefs[:50]}


def _dav_hrefs(body: bytes, base_url: str) -> list[str]:
    try:
        root = ElementTree.fromstring(body)
    except ElementTree.ParseError:
        return []
    hrefs: list[str] = []
    for href in root.findall(".//d:href", DAV_NS):
        if href.text:
            hrefs.append(urllib.parse.urljoin(base_url, href.text))
    return hrefs


def _sync_carddav(profile: dict[str, Any]) -> dict[str, Any]:
    response = _dav_propfind(profile, depth="1")
    if response.status not in {200, 207}:
        raise ValueError(f"CardDAV PROPFIND failed: {response.status}")
    hrefs = [href for href in _dav_hrefs(response.body, profile["base_url"]) if href.lower().endswith(".vcf")]
    synced = 0
    for href in hrefs:
        item = _http_request("GET", href, username=profile["username"], password=profile["password"])
        if item.status != 200 or not item.body:
            continue
        contact = _parse_vcard(item.body.decode("utf-8", errors="ignore"))
        provider_uid = contact.get("uid") or href
        with db() as conn:
            conn.execute(
                """
                INSERT INTO contacts (
                    account_id, profile_id, provider_uid, display_name, emails, phones, company, raw_vcard, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(account_id, profile_id, provider_uid) DO UPDATE SET
                    display_name = excluded.display_name,
                    emails = excluded.emails,
                    phones = excluded.phones,
                    company = excluded.company,
                    raw_vcard = excluded.raw_vcard,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (profile["account_id"], profile["id"], provider_uid, contact.get("display_name", ""), contact.get("emails", ""), contact.get("phones", ""), contact.get("company", ""), contact.get("raw", "")),
            )
        synced += 1
    return {"ok": True, "provider": "carddav", "synced": synced, "seen": len(hrefs)}


def _sync_caldav(profile: dict[str, Any]) -> dict[str, Any]:
    response = _dav_propfind(profile, depth="1")
    if response.status not in {200, 207}:
        raise ValueError(f"CalDAV PROPFIND failed: {response.status}")
    hrefs = [href for href in _dav_hrefs(response.body, profile["base_url"]) if href.lower().endswith(".ics")]
    synced = 0
    for href in hrefs:
        item = _http_request("GET", href, username=profile["username"], password=profile["password"])
        if item.status != 200 or not item.body:
            continue
        event = _parse_ics_event(item.body.decode("utf-8", errors="ignore"))
        provider_uid = event.get("uid") or href
        with db() as conn:
            conn.execute(
                """
                INSERT INTO calendar_events (
                    account_id, profile_id, provider_uid, calendar_name, title, starts_at, ends_at, attendees, location, raw_ics, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(account_id, profile_id, provider_uid) DO UPDATE SET
                    calendar_name = excluded.calendar_name,
                    title = excluded.title,
                    starts_at = excluded.starts_at,
                    ends_at = excluded.ends_at,
                    attendees = excluded.attendees,
                    location = excluded.location,
                    raw_ics = excluded.raw_ics,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (profile["account_id"], profile["id"], provider_uid, profile["name"], event.get("title", ""), event.get("starts_at", ""), event.get("ends_at", ""), event.get("attendees", ""), event.get("location", ""), event.get("raw", "")),
            )
        synced += 1
    return {"ok": True, "provider": "caldav", "synced": synced, "seen": len(hrefs)}


def _sync_activesync(profile: dict[str, Any]) -> dict[str, Any]:
    folders = _activesync_folders(profile)
    if not folders.get("ok"):
        return folders
    dav_urls = _activesync_dav_candidates(profile, folders.get("folders", []))
    errors: list[str] = []
    for url in dav_urls:
        dav_profile = dict(profile)
        dav_profile["base_url"] = url
        try:
            if profile["kind"] == "contacts":
                result = _sync_carddav(dav_profile)
            elif profile["kind"] == "calendar":
                result = _sync_caldav(dav_profile)
            else:
                raise ValueError("unsupported ActiveSync kind")
            result.update(
                {
                    "provider": "activesync",
                    "transport": "activesync-discovered-dav",
                    "source_url": url,
                    "versions": folders.get("versions", ""),
                    "commands": folders.get("commands", ""),
                }
            )
            return result
        except Exception as exc:
            errors.append(f"{url}: {exc}")
    raise ValueError("ActiveSync folder discovery succeeded, but no readable DAV collection was found for item sync: " + "; ".join(errors))


def _writable_profile(account_id: int, kind: str, user: dict[str, Any] | None = None, profile_id: int | None = None) -> dict[str, Any]:
    if profile_id:
        profile = _profile_with_secret(profile_id, user=user)
        if int(profile["account_id"]) != int(account_id) or profile["kind"] != kind:
            raise ValueError("sync profile does not match requested account/kind")
        return _writable_provider_profile(profile)
    profiles = list_sync_profiles(account_id, user=user)
    provider_order = {"carddav": 0, "caldav": 0, "activesync": 1}
    candidates = sorted(
        [profile for profile in profiles if profile["enabled"] and profile["kind"] == kind],
        key=lambda item: provider_order.get(str(item["provider"]), 9),
    )
    for candidate in candidates:
        try:
            profile = _profile_with_secret(int(candidate["id"]), user=user)
            return _writable_provider_profile(profile)
        except Exception:
            continue
    raise ValueError(f"no writable {kind} sync profile found")


def _autodiscovery_candidates(account: dict[str, Any]) -> list[dict[str, Any]]:
    email = str(account["email_address"]).strip()
    imap_host = str(account["imap_host"]).strip()
    domain = email.split("@", 1)[1].lower() if "@" in email else imap_host
    probe_profile = {
        "username": account.get("imap_username") or email,
        "password": account.get("imap_password") or "",
    }
    candidates: list[dict[str, Any]] = []
    candidates.extend(_provider_dav_candidates(email, domain))
    if domain in {"gmail.com", "googlemail.com"}:
        hosts: list[str] = []
    else:
        hosts = list(dict.fromkeys([imap_host, f"mail.{domain}", f"dav.{domain}", f"caldav.{domain}", f"carddav.{domain}", domain]))
    for host in hosts:
        base = f"https://{host}"
        candidates.extend(_well_known_dav_candidates(probe_profile, base, email))
        candidates.extend(
            [
                {
                    "kind": "contacts",
                    "provider": "carddav",
                    "name": "CardDAV contacts",
                    "base_url": f"{base}/SOGo/dav/{urllib.parse.quote(email, safe='@')}/Contacts/personal/",
                },
                {
                    "kind": "calendar",
                    "provider": "caldav",
                    "name": "CalDAV calendar",
                    "base_url": f"{base}/SOGo/dav/{urllib.parse.quote(email, safe='@')}/Calendar/personal/",
                },
                {
                    "kind": "contacts",
                    "provider": "activesync",
                    "name": "ActiveSync contacts",
                    "base_url": f"{base}/Microsoft-Server-ActiveSync",
                },
                {
                    "kind": "calendar",
                    "provider": "activesync",
                    "name": "ActiveSync calendar",
                    "base_url": f"{base}/Microsoft-Server-ActiveSync",
                },
            ]
        )
    unique: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for candidate in candidates:
        key = (candidate["kind"], candidate["provider"], candidate["base_url"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(candidate)
    return unique


def _provider_dav_candidates(email: str, domain: str) -> list[dict[str, Any]]:
    quoted = urllib.parse.quote(email, safe="@")
    if domain in {"gmail.com", "googlemail.com"}:
        return [
            {
                "kind": "contacts",
                "provider": "carddav",
                "name": "Google CardDAV contacts",
                "base_url": f"https://www.googleapis.com/carddav/v1/principals/{quoted}/lists/default/",
            },
            {
                "kind": "calendar",
                "provider": "caldav",
                "name": "Google CalDAV calendar",
                "base_url": f"https://apidata.googleusercontent.com/caldav/v2/{quoted}/events/",
            },
            {
                "kind": "calendar",
                "provider": "caldav",
                "name": "Google CalDAV root",
                "base_url": "https://apidata.googleusercontent.com/caldav/v2/",
            },
        ]
    if domain in {"icloud.com", "me.com", "mac.com"}:
        return [
            {
                "kind": "contacts",
                "provider": "carddav",
                "name": "iCloud CardDAV contacts",
                "base_url": f"https://contacts.icloud.com/{quoted}/carddavhome/card/",
            },
            {
                "kind": "calendar",
                "provider": "caldav",
                "name": "iCloud CalDAV calendar",
                "base_url": f"https://caldav.icloud.com/{quoted}/caldavhome/",
            },
        ]
    return []


def _well_known_dav_candidates(profile: dict[str, Any], base: str, email: str) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for kind, well_known, provider, prop_name, resource_tag, default_name in (
        ("contacts", "carddav", "carddav", "addressbook-home-set", "addressbook", "CardDAV contacts"),
        ("calendar", "caldav", "caldav", "calendar-home-set", "calendar", "CalDAV calendar"),
    ):
        root_url = f"{base}/.well-known/{well_known}"
        collections = _discover_dav_collections(profile, root_url, prop_name, resource_tag)
        for collection in collections:
            candidates.append(
                {
                    "kind": kind,
                    "provider": provider,
                    "name": collection.get("displayname") or default_name,
                    "base_url": collection["url"],
                }
            )
    return candidates


def _discover_dav_collections(profile: dict[str, Any], root_url: str, home_set_prop: str, resource_tag: str) -> list[dict[str, str]]:
    principal = _discover_current_user_principal(profile, root_url)
    if not principal:
        return []
    home_set = _discover_home_set(profile, principal, home_set_prop)
    if not home_set:
        return []
    return _discover_resource_collections(profile, home_set, resource_tag)


def _discover_current_user_principal(profile: dict[str, Any], root_url: str) -> str:
    body = """<?xml version="1.0" encoding="utf-8"?>
<d:propfind xmlns:d="DAV:">
  <d:prop><d:current-user-principal/><d:principal-URL/></d:prop>
</d:propfind>"""
    try:
        response = _dav_propfind_xml(profile, root_url, body, depth="0")
    except Exception:
        return ""
    if response.status not in {200, 207}:
        return ""
    root = _xml_root(response.body)
    if root is None:
        return ""
    href = _first_href(root, ".//d:current-user-principal/d:href") or _first_href(root, ".//d:principal-URL/d:href")
    return urllib.parse.urljoin(root_url, href) if href else ""


def _discover_home_set(profile: dict[str, Any], principal_url: str, prop_name: str) -> str:
    ns = "card" if prop_name.startswith("addressbook") else "cal"
    body = f"""<?xml version="1.0" encoding="utf-8"?>
<d:propfind xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav" xmlns:cal="urn:ietf:params:xml:ns:caldav">
  <d:prop><{ns}:{prop_name}/></d:prop>
</d:propfind>"""
    try:
        response = _dav_propfind_xml(profile, principal_url, body, depth="0")
    except Exception:
        return ""
    if response.status not in {200, 207}:
        return ""
    root = _xml_root(response.body)
    if root is None:
        return ""
    href = _first_href(root, f".//{ns}:{prop_name}/d:href")
    return urllib.parse.urljoin(principal_url, href) if href else ""


def _discover_resource_collections(profile: dict[str, Any], home_set_url: str, resource_tag: str) -> list[dict[str, str]]:
    body = """<?xml version="1.0" encoding="utf-8"?>
<d:propfind xmlns:d="DAV:">
  <d:prop><d:displayname/><d:resourcetype/></d:prop>
</d:propfind>"""
    try:
        response = _dav_propfind_xml(profile, home_set_url, body, depth="1")
    except Exception:
        return []
    if response.status not in {200, 207}:
        return []
    root = _xml_root(response.body)
    if root is None:
        return []
    result: list[dict[str, str]] = []
    resource_names = {resource_tag, f"{{urn:ietf:params:xml:ns:{'carddav' if resource_tag == 'addressbook' else 'caldav'}}}{resource_tag}"}
    for item in root.findall(".//d:response", DAV_NS):
        href_node = item.find("d:href", DAV_NS)
        if href_node is None or not href_node.text:
            continue
        resource_types = {node.tag for node in item.findall(".//d:resourcetype/*", DAV_NS)}
        if not resource_names.intersection(resource_types):
            continue
        display = item.find(".//d:displayname", DAV_NS)
        url = urllib.parse.urljoin(home_set_url, href_node.text)
        if not url.endswith("/"):
            url += "/"
        result.append({"url": url, "displayname": display.text.strip() if display is not None and display.text else ""})
    return result


def _sync_profile_exists(account_id: int, provider: str, kind: str, base_url: str) -> bool:
    with db() as conn:
        row = conn.execute(
            """
            SELECT id
            FROM sync_profiles
            WHERE account_id = ? AND provider = ? AND kind = ? AND base_url = ?
            """,
            (account_id, provider, kind, base_url),
        ).fetchone()
    return bool(row)


def _test_candidate_profile(profile: dict[str, Any]) -> dict[str, Any]:
    provider = profile["provider"]
    try:
        if provider == "activesync":
            result = _activesync_options(profile, timeout=5)
            result["ok"] = bool(result.get("ok") and (result.get("versions") or result.get("commands")))
            return result
        response = _dav_propfind(profile, depth="0", timeout=5)
        body = response.body.decode("utf-8", errors="ignore").lower()
        return {
            "ok": response.status == 207 and "multistatus" in body,
            "status": response.status,
            "provider": provider,
            "body_bytes": len(response.body),
        }
    except Exception as exc:
        return {"ok": False, "status": 0, "provider": provider, "error": str(exc)}


def _xml_root(body: bytes) -> ElementTree.Element | None:
    try:
        return ElementTree.fromstring(body)
    except ElementTree.ParseError:
        return None


def _first_href(root: ElementTree.Element, pattern: str) -> str:
    node = root.find(pattern, DAV_NS)
    return node.text.strip() if node is not None and node.text else ""


def _ensure_contact_allowed(account_id: int, user: dict[str, Any] | None = None) -> None:
    account = get_account(account_id, user=user)
    if not account or not account["mcp_contacts_enabled"]:
        raise ValueError("contact write not allowed for account")


def _ensure_calendar_allowed(account_id: int, user: dict[str, Any] | None = None) -> None:
    account = get_account(account_id, user=user)
    if not account or not account["mcp_calendar_enabled"]:
        raise ValueError("calendar write not allowed for account")


def _writable_provider_profile(profile: dict[str, Any]) -> dict[str, Any]:
    provider = profile["provider"]
    if provider in {"carddav", "caldav"}:
        return profile
    if provider == "activesync":
        folders = _activesync_folders(profile)
        if not folders.get("ok"):
            raise ValueError(f"ActiveSync discovery failed: {folders}")
        errors: list[str] = []
        for url in _activesync_dav_candidates(profile, folders.get("folders", [])):
            dav_profile = dict(profile)
            dav_profile["base_url"] = url
            response = _dav_propfind(dav_profile, depth="0")
            if response.status in {200, 207}:
                return dav_profile
            errors.append(f"{url}: {response.status}")
        raise ValueError("ActiveSync discovery succeeded, but no writable DAV collection was found: " + "; ".join(errors))
    raise ValueError("unsupported sync provider")


def _contact_row(contact_id: int, user: dict[str, Any] | None = None) -> dict[str, Any]:
    with db() as conn:
        if user and not user.get("is_admin"):
            row = conn.execute(
                """
                SELECT c.*
                FROM contacts c
                JOIN accounts a ON a.id = c.account_id
                WHERE c.id = ? AND a.owner_user_id = ?
                """,
                (contact_id, user["id"]),
            ).fetchone()
        else:
            row = conn.execute("SELECT * FROM contacts WHERE id = ?", (contact_id,)).fetchone()
    if not row:
        raise ValueError("contact not found")
    if row["profile_id"] is None:
        raise ValueError("contact has no writable sync profile")
    return dict(row)


def _event_row(event_id: int, user: dict[str, Any] | None = None) -> dict[str, Any]:
    with db() as conn:
        if user and not user.get("is_admin"):
            row = conn.execute(
                """
                SELECT e.*
                FROM calendar_events e
                JOIN accounts a ON a.id = e.account_id
                WHERE e.id = ? AND a.owner_user_id = ?
                """,
                (event_id, user["id"]),
            ).fetchone()
        else:
            row = conn.execute("SELECT * FROM calendar_events WHERE id = ?", (event_id,)).fetchone()
    if not row:
        raise ValueError("calendar event not found")
    if row["profile_id"] is None:
        raise ValueError("calendar event has no writable sync profile")
    return dict(row)


def _upsert_contact(profile: dict[str, Any], contact: dict[str, str], provider_uid: str) -> None:
    with db() as conn:
        conn.execute(
            """
            INSERT INTO contacts (
                account_id, profile_id, provider_uid, display_name, emails, phones, company, raw_vcard, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(account_id, profile_id, provider_uid) DO UPDATE SET
                display_name = excluded.display_name,
                emails = excluded.emails,
                phones = excluded.phones,
                company = excluded.company,
                raw_vcard = excluded.raw_vcard,
                updated_at = CURRENT_TIMESTAMP
            """,
            (profile["account_id"], profile["id"], provider_uid, contact.get("display_name", ""), contact.get("emails", ""), contact.get("phones", ""), contact.get("company", ""), contact.get("raw", "")),
        )


def _upsert_calendar_event(profile: dict[str, Any], event: dict[str, str], provider_uid: str) -> None:
    with db() as conn:
        conn.execute(
            """
            INSERT INTO calendar_events (
                account_id, profile_id, provider_uid, calendar_name, title, starts_at, ends_at, attendees, location, raw_ics, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(account_id, profile_id, provider_uid) DO UPDATE SET
                calendar_name = excluded.calendar_name,
                title = excluded.title,
                starts_at = excluded.starts_at,
                ends_at = excluded.ends_at,
                attendees = excluded.attendees,
                location = excluded.location,
                raw_ics = excluded.raw_ics,
                updated_at = CURRENT_TIMESTAMP
            """,
            (profile["account_id"], profile["id"], provider_uid, profile["name"], event.get("title", ""), event.get("starts_at", ""), event.get("ends_at", ""), event.get("attendees", ""), event.get("location", ""), event.get("raw", "")),
        )


def _resource_uid(value: Any, suffix: str) -> str:
    uid = str(value or "").strip()
    if not uid:
        uid = uuid.uuid4().hex.upper()
    if suffix and not uid.lower().endswith(suffix):
        uid = f"{uid}{suffix}"
    return uid


def _profile_resource_url(profile: dict[str, Any], uid: str, extension: str = "") -> str:
    resource = uid
    if extension and not resource.lower().endswith(extension):
        resource = f"{resource}{extension}"
    return urllib.parse.urljoin(profile["base_url"].rstrip("/") + "/", urllib.parse.quote(resource, safe=""))


def _build_vcard(uid: str, display_name: str, email: str, phone: str = "", company: str = "") -> str:
    display = display_name or email or uid
    lines = [
        "BEGIN:VCARD",
        "VERSION:3.0",
        f"UID:{_escape_vcard(uid)}",
        f"FN:{_escape_vcard(display)}",
    ]
    if email:
        for item in _split_multi(email):
            lines.append(f"EMAIL:{_escape_vcard(item)}")
    if phone:
        for item in _split_multi(phone):
            lines.append(f"TEL:{_escape_vcard(item)}")
    if company:
        lines.append(f"ORG:{_escape_vcard(company)}")
    lines.append("END:VCARD")
    return "\r\n".join(lines) + "\r\n"


def _build_ics_event(uid: str, title: str, starts_at: str, ends_at: str, location: str = "", description: str = "", attendees: str = "") -> str:
    if not title:
        raise ValueError("event title is required")
    if not starts_at:
        raise ValueError("event starts_at is required")
    if not ends_at:
        ends_at = starts_at
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    lines = [
        "BEGIN:VCALENDAR",
        "PRODID:-//Mailbridge MCP//EN",
        "VERSION:2.0",
        "BEGIN:VEVENT",
        f"UID:{_escape_ics(uid)}",
        f"SUMMARY:{_escape_ics(title)}",
        f"DTSTAMP:{stamp}",
        f"CREATED:{stamp}",
        f"LAST-MODIFIED:{stamp}",
        _ics_date_line("DTSTART", starts_at),
        _ics_date_line("DTEND", ends_at),
    ]
    if description:
        lines.append(f"DESCRIPTION:{_escape_ics(description)}")
    if location:
        lines.append(f"LOCATION:{_escape_ics(location)}")
    for attendee in _split_multi(attendees):
        if "@" in attendee:
            lines.append(f"ATTENDEE:mailto:{_escape_ics(attendee)}")
    lines.extend(["END:VEVENT", "END:VCALENDAR"])
    return "\r\n".join(lines) + "\r\n"


def _ics_date_line(name: str, value: str) -> str:
    cleaned = value.strip().replace("-", "").replace(":", "")
    if re.fullmatch(r"\d{8}", cleaned):
        return f"{name};VALUE=DATE:{cleaned}"
    if re.fullmatch(r"\d{8}T\d{6}Z?", cleaned):
        return f"{name}:{cleaned if cleaned.endswith('Z') else cleaned + 'Z'}"
    raise ValueError(f"{name} must be YYYYMMDD, YYYY-MM-DD, or UTC YYYYMMDDTHHMMSSZ")


def _split_multi(value: str) -> list[str]:
    items = [item.strip() for item in re.split(r"[,;\n]", value or "") if item.strip()]
    return list(dict.fromkeys(items))


def _escape_vcard(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace(",", "\\,").replace(";", "\\;")


def _escape_ics(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace(",", "\\,").replace(";", "\\;")


def _ics_value(raw: str, field: str) -> str:
    for line in _unfold_lines(raw):
        key, _, value = line.partition(":")
        if key.split(";", 1)[0].upper() == field.upper():
            return value
    return ""


def _parse_vcard(raw: str) -> dict[str, str]:
    unfolded = _unfold_lines(raw)
    emails: list[str] = []
    phones: list[str] = []
    result = {"raw": raw, "uid": "", "display_name": "", "company": ""}
    for line in unfolded:
        key, _, value = line.partition(":")
        name = key.split(";", 1)[0].upper()
        if name == "UID":
            result["uid"] = value.strip()
        elif name == "FN":
            result["display_name"] = value.strip()
        elif name == "ORG":
            result["company"] = value.replace(";", " ").strip()
        elif name == "EMAIL" and value.strip():
            emails.append(value.strip())
        elif name == "TEL" and value.strip():
            phones.append(value.strip())
    result["emails"] = ", ".join(dict.fromkeys(emails))
    result["phones"] = ", ".join(dict.fromkeys(phones))
    if not result["display_name"]:
        result["display_name"] = result["emails"].split(",", 1)[0] if result["emails"] else result["uid"]
    return result


def _parse_ics_event(raw: str) -> dict[str, str]:
    lines = _unfold_lines(raw)
    result = {"raw": raw, "uid": "", "title": "", "starts_at": "", "ends_at": "", "attendees": "", "location": ""}
    attendees: list[str] = []
    in_event = False
    for line in lines:
        if line == "BEGIN:VEVENT":
            in_event = True
            continue
        if line == "END:VEVENT":
            break
        if not in_event:
            continue
        key, _, value = line.partition(":")
        name = key.split(";", 1)[0].upper()
        if name == "UID":
            result["uid"] = value.strip()
        elif name == "SUMMARY":
            result["title"] = value.strip()
        elif name == "DTSTART":
            result["starts_at"] = value.strip()
        elif name == "DTEND":
            result["ends_at"] = value.strip()
        elif name == "LOCATION":
            result["location"] = value.strip()
        elif name == "ATTENDEE":
            attendees.append(value.replace("mailto:", "").strip())
    result["attendees"] = ", ".join(dict.fromkeys(attendees))
    return result


def _unfold_lines(raw: str) -> list[str]:
    lines: list[str] = []
    for line in raw.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if line.startswith((" ", "\t")) and lines:
            lines[-1] += line[1:]
        elif line:
            lines.append(line)
    return lines


def _activesync_options(profile: dict[str, Any], timeout: int = 30) -> dict[str, Any]:
    response = _http_request(
        "OPTIONS",
        profile["base_url"],
        username=profile["username"],
        password=profile["password"],
        headers={"MS-ASProtocolVersion": "14.1"},
        timeout=timeout,
    )
    return {
        "ok": response.status == 200,
        "status": response.status,
        "versions": _header_value(response.headers, "MS-ASProtocolVersions"),
        "commands": _header_value(response.headers, "MS-ASProtocolCommands"),
    }


def _activesync_folders(profile: dict[str, Any]) -> dict[str, Any]:
    options = _activesync_options(profile)
    if not options["ok"]:
        return options
    params = urllib.parse.urlencode(
        {
            "Cmd": "FolderSync",
            "User": profile["username"],
            "DeviceId": "MAILBRIDGE01",
            "DeviceType": "Mailbridge",
        }
    )
    # WBXML: FolderSync(SyncKey("0")) for EAS 14.1.
    body = bytes.fromhex("03016a00000756520330000101")
    response = _http_request(
        "POST",
        f"{profile['base_url']}?{params}",
        username=profile["username"],
        password=profile["password"],
        body=body,
        headers={
            "MS-ASProtocolVersion": "14.1",
            "Content-Type": "application/vnd.ms-sync.wbxml",
            "Accept": "application/vnd.ms-sync.wbxml",
        },
    )
    return {
        "ok": response.status == 200,
        "status": response.status,
        "versions": options.get("versions", ""),
        "commands": options.get("commands", ""),
        "folders": _extract_printable_wbxml_strings(response.body),
    }


def _activesync_dav_candidates(profile: dict[str, Any], folders: list[str]) -> list[str]:
    parsed = urllib.parse.urlparse(profile["base_url"])
    if not parsed.scheme or not parsed.netloc:
        return []
    username = urllib.parse.quote(profile["username"], safe="@")
    collection_names = _activesync_collection_names(profile["kind"], folders)
    if "personal" not in collection_names:
        collection_names.append("personal")
    base = f"{parsed.scheme}://{parsed.netloc}/SOGo/dav/{username}"
    if profile["kind"] == "contacts":
        return [f"{base}/Contacts/{urllib.parse.quote(name, safe='')}/" for name in collection_names]
    if profile["kind"] == "calendar":
        return [f"{base}/Calendar/{urllib.parse.quote(name, safe='')}/" for name in collection_names]
    return []


def _activesync_collection_names(kind: str, folders: list[str]) -> list[str]:
    prefixes = {"contacts": "vcard/", "calendar": "vevent/"}
    prefix = prefixes.get(kind)
    if not prefix:
        return []
    names: list[str] = []
    for folder in folders:
        decoded = urllib.parse.unquote(folder)
        if decoded.startswith(prefix):
            name = decoded.split("/", 1)[1].strip("/")
            if name and name not in names:
                names.append(name)
    return names


def _extract_printable_wbxml_strings(body: bytes) -> list[str]:
    strings = []
    for match in re.finditer(rb"[\x20-\x7e]{3,}", body):
        value = match.group(0).decode("utf-8", errors="ignore").strip()
        if value and value not in strings:
            strings.append(value)
    return strings[:100]


def _header_value(headers: dict[str, str], name: str) -> str:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return ""
