# Examples

## `run_batch_example.py`

Батч-маскирование целой папки с SQL (`staging/` + `marts/`). Показывает один
момент: общий `registry.json` на весь батч — `stg_orders`/`stg_customers`
встречаются и в staging, и в marts, и получают одну и ту же маску во всех
файлах.

Запуск:

```bash
python examples/run_batch_example.py
```

Результат — `examples/sql_project_masked/`, не коммитится (см. корневой
`.gitignore`).

## `sql_project/`

Синтетический, не NDA мини-проект из 4 файлов (`staging/stg_orders.sql`,
`staging/stg_customers.sql`, `marts/fct_orders.sql`, `marts/dim_customers.sql`)
— материал для демонстрации батч-режима.
