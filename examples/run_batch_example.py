# -*- coding: utf-8 -*-
"""Демо батч-маскирования папки с .sql (staging/marts) через
process_directory_mask().

Запуск:
    python examples/run_batch_example.py

Результат — examples/sql_project_masked/ (сам .sql + общий registry.json
на весь батч). Эта папка не коммитится, см. .gitignore в корне репозитория
(*_masked/, registry*.json) — registry.json внутри неё и есть ключ
деанонимизации.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from clickhouse_anonymizer import process_directory_mask  # noqa: E402

SOURCE = Path(__file__).parent / "sql_project"
TARGET = Path(__file__).parent / "sql_project_masked"

if __name__ == "__main__":
    process_directory_mask(str(SOURCE), str(TARGET))
    print(f"\nГотово. Смотри {TARGET}/ и {TARGET / 'registry.json'}")
    print(
        "Обрати внимание: stg_orders/stg_customers в staging/*.sql и marts/*.sql "
        "получили одинаковую маску во всех файлах — один общий реестр на весь батч."
    )
