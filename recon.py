#!/usr/bin/env python3
"""
BB-Recon: Bug Bounty Pre-Auth Reconnaissance Suite.

Полностью локальный движок пассивной и лёгкой активной разведки
для bug bounty программ. Читает правила программы, вытягивает scope,
rate-limit и список интересующих уязвимостей; проводит рекон
только по in-scope хостам с заголовком X-Bug-Bounty.

Примеры:
    python recon.py -p programs/beget.md -u povezlo-povezlo
    python recon.py --batch programs/ -u your_handle --passive-only -o reports/
"""
import argparse
import sys
from pathlib import Path

# Делаем пакет self-contained, независимо от CWD
sys.path.insert(0, str(Path(__file__).resolve().parent))

from core.orchestrator import Orchestrator  # noqa: E402
from utils.logger import setup_logger      # noqa: E402


RULES_EXTS = (".md", ".txt", ".html", ".htm", ".json")


def main() -> None:
    p = argparse.ArgumentParser(
        prog="bb-recon",
        description="Bug Bounty pre-auth reconnaissance suite",
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("-p", "--program",
                     help="Путь к одному файлу с правилами программы")
    src.add_argument("--batch",
                     help="Путь к директории с файлами правил")

    p.add_argument("-u", "--username", default="anonymous",
                   help="Ник на платформе для заголовка X-Bug-Bounty")
    p.add_argument("--rate", type=float, default=5.0,
                   help="Максимум запросов в секунду (по умолчанию 5)")
    p.add_argument("-o", "--out", default="./reports",
                   help="Директория для отчётов")
    p.add_argument("--proxy", default=None,
                   help="HTTP(S) прокси, например http://127.0.0.1:8080")
    p.add_argument("--passive-only", action="store_true",
                   help="Только пассивные модули")
    p.add_argument("--threads", type=int, default=5,
                   help="Число потоков для активных модулей")
    p.add_argument("--wordlist", default=None,
                   help="Путь к словарю субдоменов")
    p.add_argument("--max-subdomains", type=int, default=500,
                   help="Лимит субдоменов на программу")
    p.add_argument("--max-active-targets", type=int, default=50,
                   help="Лимит целей для активных модулей")
    p.add_argument("--log", default=None, help="Путь к лог-файлу")
    args = p.parse_args()

    p.add_argument("--deep", action="store_true",
                   help="Включить шумные модули: SSRF probe, param fuzzing")

    logger = setup_logger("recon", logfile=args.log)

    default_wordlist = Path(__file__).resolve().parent / "wordlists" / "common_subdomains.txt"
    wordlist = args.wordlist or str(default_wordlist)

    # Собираем список программ
    programs = []
    if args.batch:
        bd = Path(args.batch)
        if not bd.is_dir():
            logger.error(f"Batch директория не найдена: {bd}")
            sys.exit(1)
        for f in sorted(bd.iterdir()):
            if f.suffix.lower() in RULES_EXTS:
                programs.append(f)
    else:
        programs.append(Path(args.program))

    if not programs:
        logger.error("Не найдено ни одного файла с правилами.")
        sys.exit(1)

    logger.info(f"К обработке программ: {len(programs)}")

    for prog in programs:
        logger.info("")
        logger.info("=" * 72)
        logger.info(f"=== PROGRAM: {prog.name}")
        logger.info("=" * 72)
        try:
            orch = Orchestrator(
                rules_path=prog,
                bb_username=args.username,
                rate=args.rate,
                output_dir=args.out,
                proxy=args.proxy,
                passive_only=args.passive_only,
                threads=args.threads,
                wordlist=wordlist,
                max_subdomains=args.max_subdomains,
                max_active_targets=args.max_active_targets,
                logger=logger,
            )
            orch.run()
        except KeyboardInterrupt:
            logger.warning("Прервано пользователем.")
            sys.exit(130)
        except Exception as e:  # noqa: BLE001
            logger.exception(f"Программа упала: {e}")
            continue

    logger.info("")
    logger.info("Все программы обработаны.")


if __name__ == "__main__":
    main()