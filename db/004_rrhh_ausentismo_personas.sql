-- Migración 004: RRHH — ausentismo por persona y por mes (códigos diarios del informe de RRHH)
-- ANTES DE CORRER: crear una rama de respaldo en Neon. Requiere la migración 003 (rrhh_personal).
-- Idempotente. Son datos personales: solo los ve RRHH, Gestión de calidad y los dueños (ver MAILS_PERSONAS en el Worker).
-- Se guardan solo los códigos del informe (AA, AS, ILT, IT, DJ, VAC...), nunca el motivo ni diagnósticos.

BEGIN;

CREATE TABLE IF NOT EXISTS rrhh_aus_mes (
  periodo    text    NOT NULL CHECK (periodo ~ '^\d{4}-(0[1-9]|1[0-2])$'),
  legajo     integer NOT NULL REFERENCES rrhh_personal(legajo),
  codigos    text    NOT NULL,        -- código de cada día del mes separados por "|" (vacío = día sin código); 28 a 31 posiciones
  laborables integer,                 -- días laborables del mes de la persona, tal como figura en el informe
  fuente     text,
  actualizado_por text,
  actualizado_en  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (periodo, legajo)
);
CREATE INDEX IF NOT EXISTS rrhh_aus_mes_legajo_idx ON rrhh_aus_mes (legajo, periodo);

COMMIT;

SELECT table_name FROM information_schema.tables WHERE table_name LIKE 'rrhh_%' ORDER BY 1;
