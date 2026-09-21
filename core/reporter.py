"""Формирование итогового отчёта по программе."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from core.rules_parser import ParsedRules


def build_report(program_name: str, rules: ParsedRules,
                 findings: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "program": program_name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "rules": {
            "in_scope": rules.in_scope,
            "out_of_scope": rules.out_of_scope,
            "rate_limit": rules.rate_limit,
            "interesting_vulns": rules.interesting_vulns,
            "bb_username": rules.bb_username,
            "required_headers": rules.required_headers,
            "rewards": rules.rewards,
        },
        "findings": findings,
    }


def write_report(out_dir: Path, program_name: str,
                 report: Dict[str, Any]) -> Path:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{program_name}_report.json"
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False),
                    encoding="utf-8")
    return path