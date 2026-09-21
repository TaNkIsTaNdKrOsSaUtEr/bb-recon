"""
Анализ security-заголовков и флагов cookie.

Не атакует, только читает заголовки корневых URL. Каждое
отсутствие/слабое значение → finding со severity.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, List


_SEVERITY = {
    "missing_hsts": "medium",
    "weak_hsts": "low",
    "missing_csp": "medium",
    "weak_csp": "medium",
    "missing_x_frame": "low",
    "missing_x_content_type": "low",
    "missing_referrer_policy": "info",
    "missing_permissions_policy": "info",
    "cookie_no_secure": "medium",
    "cookie_no_httponly": "medium",
    "cookie_no_samesite": "low",
    "server_version_leak": "info",
}


def _check_cookies(r, url: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    raw = r.raw.headers.getlist("Set-Cookie") if hasattr(r.raw, "headers") else []
    if not raw:
        return out
    for cookie_str in raw:
        # формат: name=value; Secure; HttpOnly; SameSite=...
        parts = [p.strip().lower() for p in cookie_str.split(";")]
        name = cookie_str.split("=", 1)[0].strip()

        flags = {
            "secure": any(p == "secure" for p in parts),
            "httponly": any(p == "httponly" for p in parts),
            "samesite": any(p.startswith("samesite") for p in parts),
        }

        # Secure обязателен только если сайт по HTTPS
        if url.startswith("https://") and not flags["secure"]:
            out.append({
                "type": "cookie_flag",
                "url": url,
                "cookie": name,
                "issue": "cookie_no_secure",
                "severity": _SEVERITY["cookie_no_secure"],
            })
        if not flags["httponly"]:
            out.append({
                "type": "cookie_flag",
                "url": url,
                "cookie": name,
                "issue": "cookie_no_httponly",
                "severity": _SEVERITY["cookie_no_httponly"],
            })
        if not flags["samesite"]:
            out.append({
                "type": "cookie_flag",
                "url": url,
                "cookie": name,
                "issue": "cookie_no_samesite",
                "severity": _SEVERITY["cookie_no_samesite"],
            })
    return out


def _check_headers(r, url: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    h = {k.lower(): v for k, v in r.headers.items()}

    hsts = h.get("strict-transport-security", "")
    if url.startswith("https://"):
        if not hsts:
            out.append({
                "type": "header",
                "url": url,
                "issue": "missing_hsts",
                "severity": _SEVERITY["missing_hsts"],
            })
        else:
            # max-age=0 или очень маленький — слабый
            import re as _re
            m = _re.search(r"max-age=(\d+)", hsts)
            if m and int(m.group(1)) < 15552000:  # < 180 дней
                out.append({
                    "type": "header",
                    "url": url,
                    "issue": "weak_hsts",
                    "severity": _SEVERITY["weak_hsts"],
                    "value": hsts,
                })

    csp = h.get("content-security-policy", "")
    if not csp:
        out.append({
            "type": "header",
            "url": url,
            "issue": "missing_csp",
            "severity": _SEVERITY["missing_csp"],
        })
    elif ("unsafe-inline" in csp.lower()
          or "unsafe-eval" in csp.lower()
          or "default-src *" in csp.lower()):
        out.append({
            "type": "header",
            "url": url,
            "issue": "weak_csp",
            "severity": _SEVERITY["weak_csp"],
            "value": csp[:200],
        })

    xfo = h.get("x-frame-options", "")
    if not xfo and "frame-ancestors" not in csp.lower():
        out.append({
            "type": "header",
            "url": url,
            "issue": "missing_x_frame",
            "severity": _SEVERITY["missing_x_frame"],
        })

    if "x-content-type-options" not in h:
        out.append({
            "type": "header",
            "url": url,
            "issue": "missing_x_content_type",
            "severity": _SEVERITY["missing_x_content_type"],
        })

    if "referrer-policy" not in h:
        out.append({
            "type": "header",
            "url": url,
            "issue": "missing_referrer_policy",
            "severity": _SEVERITY["missing_referrer_policy"],
        })

    if "permissions-policy" not in h:
        out.append({
            "type": "header",
            "url": url,
            "issue": "missing_permissions_policy",
            "severity": _SEVERITY["missing_permissions_policy"],
        })

    # Сервер выдаёт свою версию — минорно, но в отчёт
    srv = h.get("server", "")
    import re as _re
    if _re.search(r"\d+\.\d+", srv):
        out.append({
            "type": "header",
            "url": url,
            "issue": "server_version_leak",
            "severity": _SEVERITY["server_version_leak"],
            "value": srv,
        })

    return out


def run(base_urls: List[str], session, log: Callable = print
        ) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for base in base_urls:
        r = session.get(base)
        if not r:
            continue
        # только успешные / auth-ответы, редиректы пропускаем — нечего смотреть
        if r.status_code not in (200, 401, 403):
            continue
        out.extend(_check_headers(r, base))
        out.extend(_check_cookies(r, base))
    return out
    