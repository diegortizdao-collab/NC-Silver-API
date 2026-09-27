import { neon } from "@neondatabase/serverless";

// Cambiá esto por el dominio real de tu app cuando lo tengas confirmado.
// Por ahora dejamos "*" (cualquier origen) para no trabarte mientras probamos.
const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,PUT,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...CORS_HEADERS },
  });
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: CORS_HEADERS });
    }

    const url = new URL(request.url);
    const parts = url.pathname.split("/").filter(Boolean); // ["api","nc", ...]

    try {
      if (!env.DATABASE_URL) {
        return json({ error: "Falta el binding DATABASE_URL en este Worker" }, 500);
      }
      const connectionString = await env.DATABASE_URL.get();
      const sql = neon(connectionString);
      // GET /api/nc/operarios -> detalle de operarios/productos involucrados por NC
      // (para RRHH y para la exportación Q.11 en formato oficial). Solo trae las NC
      // migradas que se repartieron entre varios operarios (nc.operario queda NULL
      // en esos casos); las NC nuevas de un solo operario ya vienen completas en
      // GET /api/nc con su propio campo "operario".
      if (request.method === "GET" && parts[1] === "nc" && parts[2] === "operarios") {
        const rows = await sql`
          SELECT o.nc_numero, o.operario, o.producto, o.maquina,
                 n.fecha_produccion, n.numero_original, n.tipo_nc_historico, n.tipo,
                 n.categoria, n.cliente, n.cantidad_piezas, n.descripcion,
                 n.con_devolucion, n.cargado_por_apellido, n.cargado_por_nombre,
                 n.operario_legajo,
                 a.estado, a.causa_raiz, a.costo_asociado
          FROM nc_operarios o
          JOIN nc n ON n.numero = o.nc_numero
          LEFT JOIN nc_analisis a ON a.nc_numero = o.nc_numero
          ORDER BY n.fecha_produccion DESC
        `;
        return json(rows);
      }

      // GET /api/nc/proximo-numero
      // Importante: las NC migradas del histórico usan un "numero" interno sintético
      // (100001+) para no chocar entre sí, y guardan el número real de Q.11 en
      // "numero_original". El próximo correlativo tiene que seguir la numeración
      // REAL (numero_original si existe, sino numero), nunca los sintéticos.
      if (request.method === "GET" && parts[1] === "nc" && parts[2] === "proximo-numero") {
        const rows = await sql`
          SELECT COALESCE(
            MAX(
              CASE
                WHEN COALESCE(numero_original, numero) < 100000
                THEN COALESCE(numero_original, numero)
              END
            ), 921
          ) + 1 AS siguiente
          FROM nc
        `;
        return json({ siguiente: rows[0].siguiente });
      }

      // GET /api/nc  -> lista completa (para el dashboard Q.11 2.0)
      if (request.method === "GET" && parts[1] === "nc" && !parts[2]) {
        const rows = await sql`
          SELECT n.*, a.estado, a.no_requiere_notificacion
          FROM nc n
          LEFT JOIN nc_analisis a ON a.nc_numero = n.numero
          ORDER BY n.numero DESC
        `;
        return json(rows);
      }

      // GET /api/nc/:numero -> una NC completa (Bloque1 + Bloque2 + notificaciones)
      if (request.method === "GET" && parts[1] === "nc" && parts[2]) {
        const numero = Number(parts[2]);
        const [nc] = await sql`SELECT * FROM nc WHERE numero = ${numero}`;
        if (!nc) return json({ error: "NC no encontrada" }, 404);
        const [analisis] = await sql`SELECT * FROM nc_analisis WHERE nc_numero = ${numero}`;
        const notificaciones = await sql`SELECT * FROM nc_notificaciones WHERE nc_numero = ${numero}`;
        return json({ ...nc, analisis: analisis || null, notificaciones });
      }

      // POST /api/nc -> crea una NC nueva (Bloque 1)
      if (request.method === "POST" && parts[1] === "nc" && !parts[2]) {
        const b = await request.json();
        const [row] = await sql`
          INSERT INTO nc (
            numero, tipo, categoria, cliente, producto, descripcion,
            fecha_produccion, operario, maquina, oti, cantidad_piezas,
            disposicion, fecha_programada, cumplido, fecha_cumplimiento,
            requiere_accion, creado_por,
            cargado_por_apellido, cargado_por_nombre, operario_legajo
          ) VALUES (
            ${b.numero}, ${b.tipo}, ${b.categoria}, ${b.cliente || null}, ${b.producto}, ${b.descripcion},
            ${b.fechaProduccion || null}, ${b.operario || null}, ${b.maquina || null}, ${b.oti || null}, ${b.cantidadPiezas || null},
            ${b.disposicion}, ${b.fechaProgramada || null}, ${b.cumplido || null}, ${b.fechaCumplimiento || null},
            ${b.requiereAccion || null}, ${b.usuario || null},
            ${b.cargadoPorApellido || null}, ${b.cargadoPorNombre || null}, ${b.operarioLegajo || null}
          )
          RETURNING *
        `;
        await sql`
          INSERT INTO nc_historial (nc_numero, campo, valor_anterior, valor_nuevo, usuario)
          VALUES (${b.numero}, 'creación', NULL, 'NC creada', ${b.usuario || null})
        `;
        return json(row, 201);
      }

      // PUT /api/nc/:numero/analisis -> crea o actualiza el Bloque 2
      if (request.method === "PUT" && parts[1] === "nc" && parts[2] && parts[3] === "analisis") {
        const numero = Number(parts[2]);
        const b = await request.json();

        const [previo] = await sql`SELECT estado FROM nc_analisis WHERE nc_numero = ${numero}`;

        const [row] = await sql`
          INSERT INTO nc_analisis (
            nc_numero, porque1, porque2, porque3, porque4, porque5, causa_raiz,
            modificar_documento, documento_detalle, accion_descripcion, responsable,
            fecha_programada_accion, fecha_verif_cumplimiento, evidencia_cumplimiento,
            fecha_verif_eficacia, evidencia_eficacia, no_requiere_notificacion, estado,
            costo_asociado, actualizado_en
          ) VALUES (
            ${numero}, ${b.porque1 || null}, ${b.porque2 || null}, ${b.porque3 || null}, ${b.porque4 || null}, ${b.porque5 || null}, ${b.causaRaiz || null},
            ${b.modificarDocumento || null}, ${b.documentoDetalle || null}, ${b.accionDescripcion || null}, ${b.responsable || null},
            ${b.fechaProgramadaAccion || null}, ${b.fechaVerifCumplimiento || null}, ${b.evidenciaCumplimiento || null},
            ${b.fechaVerifEficacia || null}, ${b.evidenciaEficacia || null}, ${b.noRequiereNotificacion || false}, ${b.estado || "Abierta"},
            ${b.costoAsociado || null}, now()
          )
          ON CONFLICT (nc_numero) DO UPDATE SET
            porque1 = EXCLUDED.porque1, porque2 = EXCLUDED.porque2, porque3 = EXCLUDED.porque3,
            porque4 = EXCLUDED.porque4, porque5 = EXCLUDED.porque5, causa_raiz = EXCLUDED.causa_raiz,
            modificar_documento = EXCLUDED.modificar_documento, documento_detalle = EXCLUDED.documento_detalle,
            accion_descripcion = EXCLUDED.accion_descripcion, responsable = EXCLUDED.responsable,
            fecha_programada_accion = EXCLUDED.fecha_programada_accion,
            fecha_verif_cumplimiento = EXCLUDED.fecha_verif_cumplimiento,
            evidencia_cumplimiento = EXCLUDED.evidencia_cumplimiento,
            fecha_verif_eficacia = EXCLUDED.fecha_verif_eficacia,
            evidencia_eficacia = EXCLUDED.evidencia_eficacia,
            no_requiere_notificacion = EXCLUDED.no_requiere_notificacion,
            estado = EXCLUDED.estado,
            costo_asociado = EXCLUDED.costo_asociado,
            actualizado_en = now()
          RETURNING *
        `;

        if (!previo || previo.estado !== row.estado) {
          await sql`
            INSERT INTO nc_historial (nc_numero, campo, valor_anterior, valor_nuevo, usuario)
            VALUES (${numero}, 'estado', ${previo ? previo.estado : null}, ${row.estado}, ${b.usuario || null})
          `;
        }

        return json(row);
      }

      // POST /api/nc/:numero/notificaciones -> agrega una fila de notificación
      if (request.method === "POST" && parts[1] === "nc" && parts[2] && parts[3] === "notificaciones") {
        const numero = Number(parts[2]);
        const b = await request.json();
        const [row] = await sql`
          INSERT INTO nc_notificaciones (nc_numero, nombre, fecha)
          VALUES (${numero}, ${b.nombre}, ${b.fecha || null})
          RETURNING *
        `;
        return json(row, 201);
      }

      return json({ error: "Ruta no encontrada" }, 404);
    } catch (err) {
      return json({ error: err.message }, 500);
    }
  },
};
