-- OM (Q.21.B): origen/justificación, plan, implementación y verificación de vigencia a los 6 meses.
ALTER TABLE om ADD COLUMN IF NOT EXISTS aprobada text;
ALTER TABLE om ADD COLUMN IF NOT EXISTS necesidad text;
ALTER TABLE om ADD COLUMN IF NOT EXISTS impacto text;
ALTER TABLE om ADD COLUMN IF NOT EXISTS meta text;
ALTER TABLE om ADD COLUMN IF NOT EXISTS plan text;
ALTER TABLE om ADD COLUMN IF NOT EXISTS fecha_implementacion date;
ALTER TABLE om ADD COLUMN IF NOT EXISTS fecha_verif_implementacion date;
ALTER TABLE om ADD COLUMN IF NOT EXISTS evidencia_implementacion text;
ALTER TABLE om ADD COLUMN IF NOT EXISTS evidencia_vigencia text;
ALTER TABLE om ADD COLUMN IF NOT EXISTS cerrada_en date;
ALTER TABLE om ADD COLUMN IF NOT EXISTS motivo_cierre text;
