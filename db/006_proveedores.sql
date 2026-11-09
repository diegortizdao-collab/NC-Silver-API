CREATE TABLE IF NOT EXISTS prov_proveedores (
 id serial PRIMARY KEY, nombre text NOT NULL UNIQUE, tipo text NOT NULL DEFAULT 'Material', critico boolean NOT NULL DEFAULT true,
 estado text NOT NULL DEFAULT 'aprobado' CHECK (estado IN ('aprobado','provisorio','discontinuado')),
 fecha_ingreso date, observaciones text, creado_por text, creado_en timestamptz NOT NULL DEFAULT now(), actualizado_en timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS prov_evaluaciones (
 id serial PRIMARY KEY, proveedor_id integer NOT NULL REFERENCES prov_proveedores(id) ON DELETE CASCADE, anio integer NOT NULL, fecha date,
 no_certificado integer, fuera_fecha integer, malas_condiciones integer, clase text CHECK (clase IN ('A','B','C','D','Sin evaluar')), observaciones text,
 actualizado_por text, actualizado_en timestamptz NOT NULL DEFAULT now(), UNIQUE (proveedor_id, anio));
