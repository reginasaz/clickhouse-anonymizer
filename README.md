# ClickHouse SQL Anonymizer (AST Engine)

Маскирует имена баз/таблиц/колонок, строки и числа в ClickHouse SQL перед
отправкой в LLM и возвращает оригинал обратно по ответу модели.

Парсинг через [`sqlglot`](https://sqlglot.com/) (`read="clickhouse"`),
fail-closed: нераспознанный синтаксис → `ManualReviewRequired`.

## Установка

```bash
pip install -r requirements.txt
```

## CLI

```bash
python clickhouse_anonymizer.py mask query.sql --reg registry.json > masked.sql
# masked.sql → LLM → ответ в answer.sql
python clickhouse_anonymizer.py unmask answer.sql --reg registry.json
```

## Как библиотека

```python
from clickhouse_anonymizer import mask_sql_ast, unmask_sql, ManualReviewRequired

sql = """
SELECT user_id, sum(order_amount) AS total_revenue
FROM internal_orders_fct
WHERE order_date >= '2024-01-01'
GROUP BY user_id
"""

try:
    masked_sql, registry = mask_sql_ast(sql)
except ManualReviewRequired as exc:
    raise SystemExit(f"Запрос не распознан: {exc}")

restored = unmask_sql(llm_answer, registry)  # llm_answer - ответ модели
```

Рабочий пример - [`app_demo.py`](app_demo.py) (`python app_demo.py`).

> `registry`/`registry.json` - ключ деанонимизации (не коммитить).

## Батч-режим (папка с .sql)

```bash
python clickhouse_anonymizer.py mask ./models --out ./models_masked
```

Один реестр на весь батч - одинаковые таблицы/колонки получают одинаковую
маску везде. Нераспарсенное уходит в `./models_masked/_MANUAL_REVIEW/` как
есть, НЕзамаскированным - тоже не коммитить.

Пример на нескольких файлах с общим реестром - в [`examples/`](examples/).

## Что маскируется

Базы, таблицы, алиасы, CTE, колонки (классификация по имени:
`id_/dt_/metric_/status_/flag_/cat_/col_`), кастомные функции/UDF (`udf_N`,
вне белого списка системных), строки (кроме белого списка токенов/дат),
числа (множитель с сохранением порядка величины). `LIMIT`/`OFFSET`/`INTERVAL`,
ординалы `ORDER BY`/`GROUP BY`, индексы и wildcard-паттерны `LIKE` не трогаются.

ClickHouse-параметр `{param:Type}` маскируется так же, как колонка.

## Ограничения

- алиасы/колонки маскируются глобально - одинаковое имя в разных
  подзапросах может получить одну маску;
- `unmask_sql` берёт только первый markdown code-блок из ответа LLM, текст
  вокруг теряется;
- белые списки (`WHITELIST_STRINGS`, `SAFE_NUMERIC_CONSTANTS`,
  `BUILTIN_FUNCTIONS`) статические, пополнение руками;
- комментарии в SQL вырезаются целиком, не маскируются;
- не проверено на DDL, materialized views, экзотических табличных функциях;
- не потокобезопасно (`AnonymizerState` общий на процесс).

## Структура

```
clickhouse_anonymizer.py - движок маскирования/демаскирования
app_demo.py              - демо как библиотеки (mask → LLM → unmask)
examples/                - батч-пример на папке .sql (staging/marts)
requirements.txt
.gitignore               - registry*.json и _MANUAL_REVIEW/ не в git
```
