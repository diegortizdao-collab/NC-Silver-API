-- Migración 001: clasificación de las NC (PR.05 Rev. 6)
-- ANTES DE CORRER: crear una rama de respaldo en Neon (Branches > Create branch) o exportar la base.
-- Se puede correr de nuevo sin romper nada (es idempotente).

BEGIN;

ALTER TABLE nc ADD COLUMN IF NOT EXISTS clasificacion text;

ALTER TABLE nc DROP CONSTRAINT IF EXISTS nc_clasificacion_chk;
ALTER TABLE nc ADD CONSTRAINT nc_clasificacion_chk CHECK (
  clasificacion IS NULL OR clasificacion IN
  ('Defectos x Control de Calidad', 'Reclamos de Clientes', 'Hallazgos de Auditoría', 'Proveedores')
);

-- Relleno inicial. tipo_nc_historico queda intacto (trazabilidad con el Q.11).
-- Regla acordada: Registro incompleto, Identificación de bultos, Material provisto por cliente y Otros
-- pasan a "Defectos x Control de Calidad". Se normalizan mayúsculas y acentos.
UPDATE nc SET clasificacion = CASE
  WHEN tipo_nc_historico IS NOT NULL THEN
    CASE
      WHEN lower(translate(tipo_nc_historico, 'áéíóúÁÉÍÓÚ', 'aeiouAEIOU')) LIKE 'reclamo%'   THEN 'Reclamos de Clientes'
      WHEN lower(translate(tipo_nc_historico, 'áéíóúÁÉÍÓÚ', 'aeiouAEIOU')) LIKE 'proveedor%' THEN 'Proveedores'
      WHEN lower(translate(tipo_nc_historico, 'áéíóúÁÉÍÓÚ', 'aeiouAEIOU')) LIKE 'hallazgo%'  THEN 'Hallazgos de Auditoría'
      ELSE 'Defectos x Control de Calidad'
    END
  WHEN tipo = 'Hallazgo de auditoría' THEN 'Hallazgos de Auditoría'
  WHEN categoria = 'Cliente'          THEN 'Reclamos de Clientes'
  WHEN categoria = 'Proveedor'        THEN 'Proveedores'
  ELSE 'Defectos x Control de Calidad'
END
WHERE clasificacion IS NULL AND tipo <> 'Op. de mejora';

CREATE INDEX IF NOT EXISTS nc_clasificacion_idx ON nc (clasificacion);

COMMIT;

-- Verificación (debe dar 0 en "sin clasificar" y los totales por clase):
SELECT clasificacion, count(*) FROM nc GROUP BY 1 ORDER BY 2 DESC;
SELECT count(*) AS sin_clasificar FROM nc WHERE clasificacion IS NULL AND tipo <> 'Op. de mejora';
-- Control de la regla de migración (tipo histórico -> clase):
SELECT tipo_nc_historico, clasificacion, count(*) FROM nc WHERE tipo_nc_historico IS NOT NULL GROUP BY 1, 2 ORDER BY 1, 2;
