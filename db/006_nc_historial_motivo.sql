-- Historial de gestión de NC: fecha del hecho (editable, con evidencia) vs fecha de registro (automática: columna "fecha").
ALTER TABLE nc_historial ADD COLUMN IF NOT EXISTS fecha_hecho date;
ALTER TABLE nc_historial ADD COLUMN IF NOT EXISTS motivo text;
CREATE INDEX IF NOT EXISTS nc_historial_nc_idx ON nc_historial (nc_numero, fecha DESC);
