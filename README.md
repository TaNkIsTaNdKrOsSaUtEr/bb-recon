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

Аргументы
Флаг	Описание
-p PATH	один файл правил
--batch DIR	папка с файлами правил
-u HANDLE	ник на платформе (для заголовка X-Bug-Bounty)
--rate N	макс. запросов в секунду (дефолт 5)
-o DIR	директория для отчётов
--proxy URL	HTTP(S)-прокси (например, для Burp)
--passive-only	только пассивные модули
--threads N	рабочие потоки (дефолт 5)
--wordlist PATH	свой словарь субдоменов
--max-subdomains	ограничение на количество субдоменов
--max-active-targets	ограничение на цели для активных модулей
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
Требования к машине

    Python 3.10+

    ~50 МБ RAM (без pandas, без ML, без torch)

    Работает на ThinkPad X230i без тормозов
