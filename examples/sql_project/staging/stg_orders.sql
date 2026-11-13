-- staging: приведение сырых заказов из CRM к единому виду
SELECT
    o.order_id,
    o.customer_id,
    o.order_date,
    o.amount AS order_amount,
    o.status
FROM raw.crm_orders AS o
WHERE o.order_date >= '2023-01-01'
