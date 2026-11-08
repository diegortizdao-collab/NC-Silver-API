-- Migración 005: Reclamos (A.03 Registro de reclamos + A.37 Informe de reclamo)
-- Correr en Neon (SQL Editor) sobre la base "Silver No Conformidades". Es idempotente y NO toca ninguna tabla existente.
-- Antes de correr: crear una rama de respaldo (Branches > Create branch), como en las migraciones anteriores.

BEGIN;

CREATE TABLE IF NOT EXISTS reclamos (
  numero            text PRIMARY KEY,                 -- como figura en el A.03 y en el A.37: '593', '45-a' (desdoblados)
  num               integer NOT NULL,                 -- parte numérica, para ordenar y calcular el próximo
  fecha             date NOT NULL,
  cliente           text NOT NULL,                    -- cliente o proveedor, según tipo
  tipo              text NOT NULL DEFAULT 'Cliente' CHECK (tipo IN ('Cliente', 'Proveedor')),
  oti               text,
  producto          text,
  cantidad          text,
  motivo            text NOT NULL,
  pertinente        boolean,
  significativo     boolean,
  accion_inmediata  text,
  observaciones     text,
  medio             text,                             -- cómo llegó el reclamo (mail, WhatsApp, teléfono…)
  devolucion        boolean,
  cant_devuelta     text,
  nc_numeros        integer[] NOT NULL DEFAULT '{}',  -- Nº de NC asociadas (el mismo número que se ve en Q.21 / Q.11)
  a37               jsonb NOT NULL DEFAULT '{}'::jsonb, -- campos del A.37: notas, factura, acciones y novedades
  a37_origen        text CHECK (a37_origen IN ('original', 'generado')),
  a37_key           text,                             -- clave en R2 del Word guardado (histórico original)
  creado_por        text,
  creado_en         timestamptz NOT NULL DEFAULT now(),
  actualizado_por   text,
  actualizado_en    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS reclamos_fecha_idx   ON reclamos (fecha);
CREATE INDEX IF NOT EXISTS reclamos_cliente_idx ON reclamos (lower(cliente));
CREATE INDEX IF NOT EXISTS reclamos_nc_idx      ON reclamos USING gin (nc_numeros);

CREATE TABLE IF NOT EXISTS reclamos_historial (
  id        bigserial PRIMARY KEY,
  numero    text NOT NULL,
  campo     text NOT NULL,
  antes     text,
  despues   text,
  usuario   text,
  fecha     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS reclamos_historial_num_idx ON reclamos_historial (numero);

COMMIT;
