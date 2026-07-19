-- Cryptarch sample data — a realistic little shop, for exercising the v0.3
-- observability surface (disk usage, table lists, row counts, index stats).
--
-- Generic: works on ANY provisioned database, run as its owning role —
--
--     psql "postgresql://mydb:PASSWORD@host:6432/mydb" -f sample-data.sql
--
-- Idempotent and self-contained: drops and recreates ONLY its own tables
-- (prefix shop_ / app_), never touches anything else. ~55k rows, ~15-25 MB
-- with indexes. Deterministic via setseed so reruns produce the same shape.

BEGIN;

SELECT setseed(0.42);

DROP TABLE IF EXISTS shop_order_items CASCADE;
DROP TABLE IF EXISTS shop_payments    CASCADE;
DROP TABLE IF EXISTS shop_orders      CASCADE;
DROP TABLE IF EXISTS shop_products    CASCADE;
DROP TABLE IF EXISTS shop_customers   CASCADE;
DROP TABLE IF EXISTS app_events       CASCADE;
DROP VIEW  IF EXISTS shop_order_totals;

-- ---- customers --------------------------------------------------------------

CREATE TABLE shop_customers (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    email      TEXT NOT NULL UNIQUE,
    full_name  TEXT NOT NULL,
    country    TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

INSERT INTO shop_customers (email, full_name, country, created_at)
SELECT
    'customer' || g || '@example.test',
    (ARRAY['Ana','Marko','Ivana','Luka','Petra','Josip','Maja','Tin','Lea','Filip'])[1 + (g % 10)]
        || ' ' ||
    (ARRAY['Horvat','Kovač','Babić','Novak','Jurić','Marić','Petrović','Tomić'])[1 + (g % 8)],
    (ARRAY['HR','DE','AT','SI','IT','NL'])[1 + floor(random() * 6)::int],
    now() - (random() * interval '730 days')
FROM generate_series(1, 2000) g;

-- ---- products ---------------------------------------------------------------

CREATE TABLE shop_products (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    sku         TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    price_cents INTEGER NOT NULL CHECK (price_cents > 0),
    stock       INTEGER NOT NULL DEFAULT 0
);

INSERT INTO shop_products (sku, name, price_cents, stock)
SELECT
    'SKU-' || lpad(g::text, 5, '0'),
    (ARRAY['Widget','Gadget','Sprocket','Flange','Gizmo','Doodad','Cog','Bracket'])[1 + (g % 8)]
        || ' ' ||
    (ARRAY['Mini','Standard','Pro','Max','Ultra'])[1 + (g % 5)]
        || ' mk' || (1 + (g % 4)),
    100 + floor(random() * 49900)::int,
    floor(random() * 500)::int
FROM generate_series(1, 500) g;

-- ---- orders -----------------------------------------------------------------

CREATE TABLE shop_orders (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    customer_id BIGINT NOT NULL REFERENCES shop_customers(id) ON DELETE CASCADE,
    status      TEXT NOT NULL CHECK (status IN ('pending','paid','shipped','cancelled')),
    placed_at   TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_orders_customer ON shop_orders(customer_id);
CREATE INDEX idx_orders_placed   ON shop_orders(placed_at);
-- Partial index: the open-order working set.
CREATE INDEX idx_orders_pending  ON shop_orders(placed_at) WHERE status = 'pending';

INSERT INTO shop_orders (customer_id, status, placed_at)
SELECT
    1 + floor(random() * 2000)::int,
    (ARRAY['pending','paid','paid','shipped','shipped','shipped','cancelled'])[1 + floor(random() * 7)::int],
    now() - (random() * interval '365 days')
FROM generate_series(1, 8000);

-- ---- order items (composite PK, two FKs) ------------------------------------

CREATE TABLE shop_order_items (
    order_id         BIGINT  NOT NULL REFERENCES shop_orders(id) ON DELETE CASCADE,
    product_id       BIGINT  NOT NULL REFERENCES shop_products(id),
    qty              INTEGER NOT NULL CHECK (qty > 0),
    unit_price_cents INTEGER NOT NULL,
    PRIMARY KEY (order_id, product_id)
);
CREATE INDEX idx_items_product ON shop_order_items(product_id);

-- 1-5 distinct products per order.
INSERT INTO shop_order_items (order_id, product_id, qty, unit_price_cents)
SELECT DISTINCT ON (o.id, p.pid)
    o.id,
    p.pid,
    1 + floor(random() * 4)::int,
    pr.price_cents
FROM shop_orders o
CROSS JOIN LATERAL (
    SELECT 1 + floor(random() * 500)::int AS pid
    FROM generate_series(1, 1 + floor(random() * 4 + o.id * 0)::int)
) p
JOIN shop_products pr ON pr.id = p.pid;

-- ---- payments ---------------------------------------------------------------

CREATE TABLE shop_payments (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    order_id     BIGINT NOT NULL REFERENCES shop_orders(id) ON DELETE CASCADE,
    amount_cents INTEGER NOT NULL,
    method       TEXT NOT NULL,
    paid_at      TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_payments_order ON shop_payments(order_id);

INSERT INTO shop_payments (order_id, amount_cents, method, paid_at)
SELECT
    o.id,
    COALESCE(i.total, 0),
    (ARRAY['card','bank_transfer','paypal','cash'])[1 + floor(random() * 4)::int],
    o.placed_at + interval '1 hour'
FROM shop_orders o
JOIN LATERAL (
    SELECT SUM(qty * unit_price_cents)::int AS total
    FROM shop_order_items WHERE order_id = o.id
) i ON TRUE
WHERE o.status IN ('paid', 'shipped');

-- ---- app events (jsonb bulk — this is where the megabytes live) -------------

CREATE TABLE app_events (
    id        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    entity    TEXT NOT NULL,
    entity_id BIGINT NOT NULL,
    action    TEXT NOT NULL,
    at        TIMESTAMPTZ NOT NULL,
    payload   JSONB NOT NULL
);
CREATE INDEX idx_events_entity ON app_events(entity, entity_id);
CREATE INDEX idx_events_at     ON app_events(at);

INSERT INTO app_events (entity, entity_id, action, at, payload)
SELECT
    (ARRAY['order','customer','product'])[1 + (g % 3)],
    1 + floor(random() * 2000)::int,
    (ARRAY['created','updated','viewed','exported','flagged'])[1 + (g % 5)],
    now() - (random() * interval '365 days'),
    jsonb_build_object(
        'source', (ARRAY['web','api','import','admin'])[1 + (g % 4)],
        'ip', '10.10.' || floor(random() * 255)::int || '.' || floor(random() * 255)::int,
        'user_agent', 'Mozilla/5.0 (sample) rev/' || g,
        'trace', md5(g::text) || md5((g * 7)::text),
        'changes', jsonb_build_array(
            jsonb_build_object('field', 'status', 'old', 'a', 'new', 'b'),
            jsonb_build_object('field', 'note',   'old', NULL, 'new', repeat('x', 40))
        )
    )
FROM generate_series(1, 15000) g;

-- ---- a view, so the catalog has one -----------------------------------------

CREATE VIEW shop_order_totals AS
SELECT o.id, o.customer_id, o.status, o.placed_at,
       COALESCE(SUM(i.qty * i.unit_price_cents), 0) AS total_cents
FROM shop_orders o
LEFT JOIN shop_order_items i ON i.order_id = o.id
GROUP BY o.id;

COMMIT;

-- Fresh planner stats so reltuples-based approximate row counts are honest.
-- Scoped to our tables: a bare ANALYZE warns on system catalogs when run
-- as a plain owner role.
ANALYZE shop_customers, shop_products, shop_orders, shop_order_items,
        shop_payments, app_events;

-- A little receipt.
SELECT relname AS "table",
       to_char(reltuples, 'FM999999') AS "~rows",
       pg_size_pretty(pg_total_relation_size(oid)) AS "size (incl. indexes)"
FROM pg_class
WHERE relkind = 'r' AND relname LIKE ANY (ARRAY['shop\_%', 'app\_%'])
ORDER BY pg_total_relation_size(oid) DESC;
