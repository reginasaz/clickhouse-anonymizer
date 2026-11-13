-- marts: факт заказов с присоединённым клиентом
SELECT
    o.order_id,
    o.customer_id,
    cu.loyalty_tier,
    o.order_amount,
    o.status,
    o.order_date
FROM stg_orders AS o
LEFT JOIN stg_customers AS cu
    ON o.customer_id = cu.customer_id
WHERE o.status != 'canceled'
