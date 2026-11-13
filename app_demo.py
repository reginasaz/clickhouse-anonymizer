# -*- coding: utf-8 -*-
"""Демо: использование clickhouse_anonymizer.py как библиотеки, без CLI.

Берём "боевой" SQL с реальными именами -> mask_sql_ast() -> получаем SQL,
безопасный для отправки в LLM, плюс registry (ключ) -> имитируем ответ
модели -> unmask_sql() возвращает реальные имена обратно.

Запуск:
    python app_demo.py
"""

from clickhouse_anonymizer import ManualReviewRequired, mask_sql_ast, unmask_sql

SQL = """
SELECT
    user_id,
    sum(order_amount) AS total_revenue
FROM internal_orders_fct
WHERE order_date >= '2024-01-01'
  AND status = 'completed'
GROUP BY user_id
HAVING total_revenue > 1000
"""


def fake_llm_call(masked_sql: str) -> str:
    """Заглушка вместо реального вызова LLM API.

    Возвращает ответ в формате "текст + ```sql блок + текст", как обычно и
    отвечает модель — чтобы ниже было видно известное ограничение
    unmask_sql(): текст вокруг кода при демаскировании отбрасывается
    (см. README, раздел "Известные ограничения").
    """
    return f"""Вот тот же запрос, с комментарием для читаемости:

```sql
-- отфильтровали результат через HAVING
{masked_sql.strip()}
```

Если нужно, могу добавить сортировку по total_revenue.
"""


def main() -> None:
    try:
        masked_sql, registry = mask_sql_ast(SQL)
    except ManualReviewRequired as exc:
        print(f"Запрос не распознан, нужен ручной разбор: {exc}")
        return

    print("Замаскированный SQL (это и только это уходит в LLM):")
    print(masked_sql)

    llm_answer = fake_llm_call(masked_sql)
    print("\nОтвет LLM (маски внутри, как их видит модель):")
    print(llm_answer)

    restored = unmask_sql(llm_answer, registry)
    print("Восстановленный ответ (реальные имена вернулись):")
    print(restored)
    print(
        "\n(Пояснительный текст LLM вокруг ```sql блока выше пропал — это "
        "известное ограничение, см. README.)"
    )

    print("\nРеестр (ключ деанонимизации — никогда не коммитить!):")
    for mask, original in registry.items():
        print(f"  {mask} -> {original}")


if __name__ == "__main__":
    main()
