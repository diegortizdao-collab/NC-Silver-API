-- Migración 002: Apéndice C (indicadores de objetivos de calidad) — I.09 Rev. 012
-- ANTES DE CORRER: crear una rama de respaldo en Neon (Branches > Create branch).
-- Idempotente: se puede correr de nuevo sin romper nada. No toca las tablas de NC.

BEGIN;

-- OTI por mes de entrega pactada (base común de quejas, devoluciones, fallas y atrasos).
CREATE TABLE IF NOT EXISTS apc_oti_mensual (
  mes        text PRIMARY KEY CHECK (mes ~ '^\d{4}-(0[1-9]|1[0-2])$'),
  oti_total  integer NOT NULL DEFAULT 0,   -- OTI pactadas en el mes
  oti_ent    integer NOT NULL DEFAULT 0,   -- OTI entregadas (con fecha de remito conformado)
  atrasos    integer NOT NULL DEFAULT 0,   -- entregadas con fecha enviada > fecha pactada
  fuente     text,
  actualizado_por text,
  actualizado_en  timestamptz NOT NULL DEFAULT now()
);

-- Valores de los indicadores que no salen de las NC (scrap, eficiencia, set up, ingresos vs egresos,
-- ausentismo, satisfacción, proveedores, capacitación). periodo = 'YYYY-MM' (mensual) o 'YYYY' (anual).
CREATE TABLE IF NOT EXISTS apc_valores (
  indicador  text NOT NULL,
  periodo    text NOT NULL CHECK (periodo ~ '^\d{4}(-(0[1-9]|1[0-2]))?$'),
  valor      numeric,          -- el valor ya calculado (fracción: 0.0357 = 3,57 %; set up en horas)
  num        numeric,          -- numerador (para acumular ponderado)
  den        numeric,          -- denominador
  fuente     text,
  actualizado_por text,
  actualizado_en  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (indicador, periodo)
);

-- Períodos cerrados (congelados). periodo = 'YYYY-MM' o 'YYYY'.
CREATE TABLE IF NOT EXISTS apc_cierres (
  periodo    text PRIMARY KEY,
  cerrado_por text NOT NULL,
  cerrado_en  timestamptz NOT NULL DEFAULT now()
);

COMMIT;

SELECT table_name FROM information_schema.tables WHERE table_name LIKE 'apc_%' ORDER BY 1;
