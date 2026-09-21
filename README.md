# BB-Recon

Локальный пассивный + слабо-активный рекон-движок для bug bounty.
Работает по правилам программы: сам парсит scope, ограничения по запросам
и список интересующих классов уязвимостей, затем проводит разведку
только по in-scope целям, добавляя к каждому запросу `X-Bug-Bounty`.

## Что делает

### Passive
- DNS-энумерация (A/AAAA/MX/TXT/CNAME/SOA)
- Субдомены через Certificate Transparency (crt.sh)
- DNS-брутфорс по словарю (`wordlists/common_subdomains.txt`)
- Исторические URL через Wayback Machine (CDX API)

### Active (light, non-intrusive)
- HTTP-probe (заголовки, сервер, технологии)
- Sensitive paths (`.git/HEAD`, `.env`, `swagger.json`, `/server-status`, ...)
- CORS-misconfig
- Open Redirect (по списку типовых параметров)
- SSRF-probe (с проверкой на маркеры `root:x:0:0`, metadata-endpoint)
- Error-leak param-fuzzing (SQLi-сигнатуры, template-injection, path traversal)

## Что не делает
- Не сканирует деструктивно
- Не логинится, не регистрируется
- Не отправляет payload'ы, которые могут привести к DoS / modify data
- Не заходит за пределы scope (проверка перед каждым запросом)

## Установка

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Использование

Одна программа:

```bash
python recon.py -p programs/hackerone_example.md -u your_handle
```

Батч по папке (для запуска на ночь):

```bash
python recon.py --batch programs/ -u your_handle --passive-only -o reports/
```

Или с активными модулями:

```bash
python recon.py --batch programs/ -u your_handle -o reports/ --threads 5 --rate 5
```

| Флаг | Аргумент | Описание |
|------|----------|----------|
| `-p` | `PATH` | один файл правил |
| `--batch` | `DIR` | папка с файлами правил |
| `-u` | `HANDLE` | ник на платформе (для заголовка `X-Bug-Bounty`) |
| `--rate` | `N` | макс. запросов в секунду (дефолт 5) |
| `-o` | `DIR` | директория для отчётов |
| `--proxy` | `URL` | HTTP(S)-прокси (например, для Burp) |
| `--threads` | `N` | рабочие потоки (дефолт 5) |
| `--wordlist` | `PATH` | свой словарь субдоменов |
| `--max-subdomains` | — | ограничение на количество субдоменов |
| `--max-active-targets` | — | ограничение на цели для активных модулей |

Формат отчёта

reports/<program_name>_report.json — единственный артефакт:

```json
{
  "program": "example_program",
  "generated_at": "2026-08-15T...",
  "rules": { "in_scope": [...], "out_of_scope": [...], "rate_limit": 5, "interesting_vulns": [...] },
  "findings": {
    "dns": [...],
    "subdomains": [...],
    "http_probe": [...],
    "misconfig": [...],
    ...
  }
}
```

Этика

Инструмент создан для использования только в рамках публичных bug bounty программ,
у которых есть явный scope. Скрипт проверяет каждый хост по scope из правил
перед отправкой запроса. Не снимайте эти проверки — они защищают вас от банов
и от нелегального сканирования.


MIT License

Copyright (c) 2026 TaNkIsTaNdKrOsSaUtEr

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

