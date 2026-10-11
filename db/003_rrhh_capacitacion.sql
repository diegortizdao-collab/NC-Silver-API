-- Migración 003: RRHH — personal, programa de capacitación (A.18) y registro de asistencia (A.14 / A.26)
-- ANTES DE CORRER: crear una rama de respaldo en Neon (Branches > Create branch).
-- Idempotente. No toca las tablas de NC ni del Apéndice C.
-- Son datos personales: solo los ven las cuentas de RRHH y las generales (no hay lectura pública).

BEGIN;

CREATE TABLE IF NOT EXISTS rrhh_personal (
  legajo     integer PRIMARY KEY,           -- "Nº Op" del A.26
  nombre     text NOT NULL,
  activo     boolean NOT NULL DEFAULT true,
  actualizado_por text,
  actualizado_en  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS rrhh_capacitaciones (
  id           serial PRIMARY KEY,
  anio         integer NOT NULL,                       -- año del programa (A.18)
  tema         text NOT NULL,
  instructor   text,
  tipo         text CHECK (tipo IN ('Interno','Externo')),
  periodo_plan text,                                   -- fecha o período planificado (texto libre: "Noviembre", "2026-06")
  fecha_plan   date,
  destinatarios text,
  lugar        text,
  programada   boolean NOT NULL DEFAULT true,          -- false = no programada (se registra pero no entra en el denominador)
  estado       text NOT NULL DEFAULT 'Agendada' CHECK (estado IN ('Agendada','Cumplida','Reprogramada','Cancelada')),
  fecha_real   date,                                   -- fecha en que se dictó (A.14 "Fecha")
  duracion     text,                                   -- A.14 "Duración"
  temas        text,                                   -- A.14 "Temas a desarrollar"
  observaciones text,
  -- Evaluación de la efectividad (A.14)
  efect_fecha_programada date,
  efect_evaluacion text,                               -- A.14 "Evaluación:" (texto libre)
  efect_efectiva   boolean,
  efect_fecha_real date,
  efect_evaluador  text,
  efect_acciones   text,
  actualizado_por text,
  actualizado_en  timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE rrhh_capacitaciones ADD COLUMN IF NOT EXISTS efect_evaluacion text;
CREATE INDEX IF NOT EXISTS rrhh_cap_anio_idx ON rrhh_capacitaciones (anio);

CREATE TABLE IF NOT EXISTS rrhh_asistencia (
  cap_id    integer NOT NULL REFERENCES rrhh_capacitaciones(id) ON DELETE CASCADE,
  legajo    integer NOT NULL REFERENCES rrhh_personal(legajo),
  calificacion text CHECK (calificacion IN ('S','PS','NS')),   -- Satisfactorio / Poco satisfactorio / No satisfactorio
  observaciones text,
  PRIMARY KEY (cap_id, legajo)
);

COMMIT;

SELECT table_name FROM information_schema.tables WHERE table_name LIKE 'rrhh_%' ORDER BY 1;
