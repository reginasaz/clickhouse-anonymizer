SELECT
    customer_id,
    email,
    loyalty_tier,
    CASE
        WHEN loyalty_tier = 'gold' THEN 3
        WHEN loyalty_tier = 'silver' THEN 2
        ELSE 1
    END AS tier_rank
FROM stg_customers
