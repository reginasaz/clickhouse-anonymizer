-- staging: клиенты из CRM
SELECT
    c.customer_id,
    c.email,
    c.registration_date,
    c.loyalty_tier
FROM raw.crm_customers AS c
