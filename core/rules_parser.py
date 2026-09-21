"""
Эвристический парсер файлов правил bug bounty программ.

Поддерживает markdown/plain text/HTML. Вытягивает:
  * in-scope и out-of-scope домены (в т.ч. wildcard *.domain.tld)
  * rate-limit (запросов в секунду)
  * список интересующих классов уязвимостей
  * таблицу выплат (по уровням)
  * требуемые заголовки (X-Bug-Bounty и т.п.)
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional


# --- Утилиты нормализации текста ----------------------------------------

_HTML_TAG_RE = re.compile(r"<[^>]+>")
_HTML_ENT_RE = re.compile(r"&[a-z]+;", re.I)


def _looks_like_html(raw: str) -> bool:
    return bool(re.search(r"<\s*(html|body|div|p|section|article|h[1-6])\b", raw, re.I))


def _strip_html(raw: str) -> str:
    txt = _HTML_TAG_RE.sub(" ", raw)
    txt = _HTML_ENT_RE.sub(" ", txt)
    return re.sub(r"[ \t]+", " ", txt)


def _normalize(raw: str) -> str:
    return _strip_html(raw) if _looks_like_html(raw) else raw


# --- Регулярки ----------------------------------------------------------

RE_URL_HOST = re.compile(r"https?://([a-z0-9\.\-]+)", re.I)
RE_WILDCARD = re.compile(r"\*\.([a-z0-9\-]+(?:\.[a-z0-9\-]+)+)", re.I)
RE_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b",
    re.I,
)

# Мусор, который не должен попадать в scope
_NOISE_TLDS = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
    ".css", ".js", ".map", ".woff", ".woff2", ".ttf", ".eot",
    ".pdf", ".md", ".txt", ".xml", ".json", ".yml", ".yaml",
    ".zip", ".tar", ".gz", ".7z", ".rar", ".ini", ".exe", 
    ".dll", ".sys", ".bak", ".log", ".conf", ".cfg",
)
_NOISE_DOMAINS = {
    "example.com", "example.org", "schemas.microsoft.com",
    "developer.mozilla.org", "w3.org", "learn.microsoft.com",
    "tools.ietf.org", "datatracker.ietf.org", "docs.microsoft.com",
    "docs.python.org", "github.com", "raw.githubusercontent.com",
    "google.com", "youtube.com", "yandex.ru",
}

_APPSTORE_DOMAINS = {
    "apps.apple.com", "play.google.com", "itunes.apple.com",
    "appgallery.huawei.com", "rustore.ru", "appstore.com",
}

# Обратный DNS: com.example.app, org.foo.bar, io.myapp
_REVERSE_DNS = re.compile(r"^(com|org|net|io|ru|de|uk|fr|es|it)\.[a-z0-9\-]+", re.I)

# Rate limit
RE_RATE = [
    re.compile(r"(\d+)\s*(?:requests?|запрос\w*)\s*(?:per|в|\/)\s*(?:second|секунд\w*)", re.I),
    re.compile(r"(\d+)\s*(?:r\/s|req\/s|rps)\b", re.I),
    re.compile(r"(?:не более|no more than|limit[^\n]{0,20}?)\s*(\d+)\s*(?:запрос\w*|requests?|req\b)", re.I),
]

# Интересующие классы уязвимостей
INTERESTING_VULNS: Dict[str, re.Pattern] = {
    "RCE": re.compile(r"\bRCE\b|remote\s+code\s+execution|удаленн\w+\s+исполнени\w+\s+код", re.I),
    "SQLi": re.compile(r"\bSQL[-\s]?i(njection)?\b|SQL[-\s]?инъекц", re.I),
    "SSRF": re.compile(r"\bSSRF\b|server[-\s]?side\s+request\s+forgery", re.I),
    "LFI": re.compile(r"\bLFI\b|local\s+file\s+inclusion|чтени\w+\s+файл", re.I),
    "RFI": re.compile(r"\bRFI\b|remote\s+file\s+inclusion", re.I),
    "XXE": re.compile(r"\bXXE\b|XML\s+external\s+entity", re.I),
    "IDOR": re.compile(r"\bIDOR\b|insecure\s+direct\s+object\s+reference", re.I),
    "XSS": re.compile(r"\bXSS\b|cross[-\s]?site\s+scripting", re.I),
    "CSRF": re.compile(r"\bCSRF\b|cross[-\s]?site\s+request\s+forgery", re.I),
    "OpenRedirect": re.compile(r"open[-\s]?redirect|открыт\w+\s+редирект", re.I),
    "PathTraversal": re.compile(r"path[-\s]?traversal|directory\s+traversal|обход\s+каталог", re.I),
    "SubdomainTakeover": re.compile(r"subdomain\s+takeover|захват\s+субдомен", re.I),
    "InfoDisclosure": re.compile(r"information\s+disclosure|утечк\w+\s+информ", re.I),
    "AuthBypass": re.compile(r"auth(?:entication|orization)?\s+bypass|обход\s+аутентификац", re.I),
    "PrivEsc": re.compile(r"privilege\s+escalation|повышени\w+\s+привилег", re.I),
    "BusinessLogic": re.compile(r"business\s+logic|логическ\w+\s+уязв", re.I),
}

# Заголовки, по которым опознают трафик исследователя
RE_HEADER = re.compile(r"(X-[A-Za-z\-]*(?:Bug|Bounty|Hacker|Intigriti|YesWeHack|Bugcrowd)[A-Za-z\-]*)\s*[:=]\s*([\w\-\.]+)", re.I)

_RE_EMAIL = re.compile(r"[a-z0-9\._%+\-]+@[a-z0-9\.\-]+\.[a-z]{2,24}", re.I)

_PLACEHOLDER_VALUES = {
    "username", "your_handle", "your-handle", "yourhandle",
    "ник", "handle", "nick", "your_nick", "your_username",
    "example", "test",
}

# Секции
RE_IN_SCOPE = re.compile(
    r"(in[-\s]?scope|scope\b|область\s+действия|где\s+искать|"
    r"скоуп|what\s+to\s+test|targets?)\b",
    re.I,
)
RE_OUT_SCOPE = re.compile(
    r"(out[-\s]?of[-\s]?scope|вне\s+скоупа|что\s+не\s+нужно\s+присылать|"
    r"не\s+претендует\s+на\s+вознаграждение|not\s+in\s+scope|"
    r"out\s+of\s+scope)",
    re.I,
)

# Выплаты
RE_REWARD = re.compile(
    r"(Critical|High|Medium|Low|Критическ\w*|Высок\w*|Средн\w*|Низк\w*)"
    r"[^\n]{0,60}?([\d][\d\s\.,]{2,15})\s*(?:₽|руб|RUB|USD|\$|EUR|€)",
    re.I,
)


class ParsedRules:
    def __init__(self) -> None:
        self.in_scope: List[str] = []
        self.out_of_scope: List[str] = []
        self.interesting_vulns: List[str] = []
        self.rate_limit: Optional[float] = None
        self.bb_username: str = "anonymous"
        self.required_headers: Dict[str, str] = {}
        self.rewards: Dict[str, str] = {}
        self.raw_text: str = ""


def _clean_domain(d: str) -> Optional[str]:
    d = d.strip().lower().rstrip(".,;:")
    if not d or len(d) < 4:
        return None
    if d in _APPSTORE_DOMAINS:          # ← НОВОЕ
        return None                      # ← НОВОЕ
    if _REVERSE_DNS.match(d):           # ← НОВОЕ
        return None            
    if d.endswith(_NOISE_TLDS):
        return None
    if d in _NOISE_DOMAINS:
        return None
    if d.count(".") < 1:
        return None
    # отсекаем варианты типа "ru.example.com" без учёта регистра
    return d


def _extract_domains(text: str) -> List[str]:
    if not text:
        return []
    found = set()
    for m in RE_WILDCARD.finditer(text):
        base = _clean_domain(m.group(1))
        if base:
            found.add("*." + base)
    for m in RE_URL_HOST.finditer(text):
        h = _clean_domain(m.group(1).split(":")[0])
        if h:
            found.add(h)
    for m in RE_DOMAIN.finditer(text):
        h = _clean_domain(m.group(0))
        if h:
            found.add(h)
    return sorted(found)


def _split_sections(text: str) -> Dict[str, str]:
    """Собирает ВСЕ in- и out-секции, чтобы не зацепиться за оглавление.

    Склеиваем куски одного типа через '\\n'. Домены впоследствии кладутся
    в set, поэтому дубликаты из оглавления и тела не мешают.
    """
    markers = []
    for m in RE_IN_SCOPE.finditer(text):
        markers.append((m.start(), "in"))
    for m in RE_OUT_SCOPE.finditer(text):
        markers.append((m.start(), "out"))
    if not markers:
        return {"in": text}

    markers.sort()

    chunks: Dict[str, List[str]] = {"in": [], "out": []}
    for i, (pos, kind) in enumerate(markers):
        end = markers[i + 1][0] if i + 1 < len(markers) else len(text)
        chunks[kind].append(text[pos:end])

    result: Dict[str, str] = {}
    for kind in ("in", "out"):
        if chunks[kind]:
            result[kind] = "\n".join(chunks[kind])
    return result

def parse_rules(path: Path) -> ParsedRules:
    raw = Path(path).read_text(encoding="utf-8", errors="replace")
    text = _normalize(raw)
    text = _RE_EMAIL.sub(" ", text)     # ← НОВОЕ: вырезаем email-адреса
    pr = ParsedRules()
    pr.raw_text = text
    sections = _split_sections(text)
    in_text = sections.get("in", text)
    out_text = sections.get("out", "")

    pr.in_scope = _extract_domains(in_text)
    pr.out_of_scope = _extract_domains(out_text)

    # Удаляем из in-scope то, что явно в out-of-scope
    if pr.out_of_scope:
        out_set = set(pr.out_of_scope)
        pr.in_scope = [d for d in pr.in_scope if d not in out_set]

    # Rate-limit
    for rx in RE_RATE:
        m = rx.search(text)
        if m:
            try:
                pr.rate_limit = float(m.group(1))
                break
            except ValueError:
                continue

    # Интересные классы уязвимостей
    for name, rx in INTERESTING_VULNS.items():
        if rx.search(text):
            pr.interesting_vulns.append(name)

    # Кастомные заголовки
    for m in RE_HEADER.finditer(text):
        key = m.group(1)
        val = m.group(2).strip().rstrip(".")
        if val.lower() in _PLACEHOLDER_VALUES or len(val) < 3:
            continue
        pr.required_headers[key] = val
    # Выплаты
    for m in RE_REWARD.finditer(text):
        level = m.group(1).capitalize()
        pr.rewards.setdefault(level, m.group(2).strip())

    return pr
