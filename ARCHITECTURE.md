# Архитектура BB-Recon

## Обзор
Легковесный (~2400 LOC), модульный движок для пассивного и слабо-активного рекона в рамках bug bounty. Главная особенность: строгое соблюдение scope и rate-limit *до* отправки любого HTTP-запроса.

## Структура проекта
- `recon.py`: Точка входа. Парсит аргументы CLI и запускает `Orchestrator`.
- `core/`: Мозг системы.
  - `rules_parser.py`: Эвристический парсер Markdown-файлов программ (извлекает in/out scope, rate-limit, интересные уязвимости).
  - `scope_manager.py`: Валидатор доменов. Поддерживает wildcard (`*.example.com`) и строгое исключение out-of-scope.
  - `orchestrator.py`: Координирует поток данных между пассивными и активными модулями.
- `modules/`:
  - `passive/`: `dns_enum`, `subdomain_enum` (crt.sh + bruteforce), `wayback`.
  - `active/`: `http_probe`, `misconfig_scan`, `cors_check`, `ssrf_probe` и др. (только non-intrusive проверки).
- `utils/`:
  - `http_client.py`: Кастомная обертка над `requests.Session`. Реализует **Token Bucket** для rate limiting, circuit breaker для мертвых хостов и автоматическую инъекцию заголовка `X-Bug-Bounty`.
  - `dns_utils.py`: Утилиты для резолвинга.

## Поток данных (Data Flow)
1. `recon.py` инициализирует `Orchestrator` с файлом правил.
2. `rules_parser` извлекает `in_scope`, `out_of_scope` и `rate_limit`.
3. `ScopeManager` инициализируется этими правилами.
4. `ReconSession` (HTTP-клиент) привязывается к `ScopeManager` и `TokenBucket`.
5. Запускаются пассивные модули → собираются субдомены и URL.
6. URL фильтруются через `ScopeManager.is_in_scope()`.
7. К отфильтрованным целям применяются активные модули (с соблюдением rate-limit).
8. `reporter.py` агрегирует все находки в единый `reports/<program>_report.json`.

## Безопасность и этика
- **Scope Guard:** Каждый URL проверяется через `ScopeManager` внутри `ReconSession.request()` *перед* выполнением `session.get/post`.
- **Rate Limiting:** Реализован через алгоритм Token Bucket, а не блокирующий `sleep`, что позволяет эффективно использовать пул потоков.
- **Non-intrusive:** Активные модули не отправляют деструктивные пейлоады (только чтение заголовков, базовые пути, маркеры SSRF).
