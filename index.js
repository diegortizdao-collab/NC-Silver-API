import { neon } from "@neondatabase/serverless";

// Solo las apps publicadas en GitHub Pages pueden llamar a la API desde el navegador.
const ALLOWED_ORIGIN = "https://diegortizdao-collab.github.io";
const CORS_HEADERS = {
  "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
  "Access-Control-Allow-Methods": "GET,POST,PUT,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type,Authorization",
  "Vary": "Origin",
};

// ---------------------------------------------------------------------------
// Acceso: lista blanca de mails + contraseña compartida (secreto del Worker).
// La contraseña NUNCA va en el código ni en el repo: wrangler secret put APP_PASSWORD
// El token se firma con AUTH_SECRET (wrangler secret put AUTH_SECRET, texto largo al azar).
// ---------------------------------------------------------------------------
const MAILS_AUTORIZADOS = new Set([
  "diegortizdao@gmail.com",
  "gestioncalidad@silverindustrial.com.ar",
  "dortiz@escorial.com.ar",
  "controlcalidad@silverindustrial.com.ar",
  "controldeproducion@silverindustrial.com.ar", // sic: así lo informó el usuario; confirmar ortografía
]);
const TOKEN_HORAS = 12;

// Tipos de informe con numeración propia (PR.05 Rev. 6). El número interno es offset+n para no chocar
// con las NC; el número real queda en numero_original (mismo criterio que el histórico del Q.11).
//  - OM (Oportunidades de mejora): se cargan a mano las históricas (1 a 244) y las nuevas siguen desde la 245.
//  - Hallazgos de auditoría: serie nueva desde 2026 (los 5 hallazgos viejos del Q.11 quedan con la numeración de NC).
const TIPO_OM = "Op. de mejora";
const TIPO_HA = "Hallazgo de auditoría";
const SERIES = {
  om: { tipo: TIPO_OM, offset: 200000, base: 244 }, // el próximo nunca baja de la 245
  ha: { tipo: TIPO_HA, offset: 300000, base: 0 },
};
const serieDeTipo = (tipo) => (tipo === TIPO_OM ? SERIES.om : tipo === TIPO_HA ? SERIES.ha : null);
const NC_MAX_INTERNO = 200000; // los números internos de NC (incl. históricas 100001+) quedan por debajo
const CLASES_NC = ["Defectos x Control de Calidad", "Reclamos de Clientes", "Hallazgos de Auditoría", "Proveedores"];
const enc = new TextEncoder();

const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const b64uStr = (s) => b64u(enc.encode(s));
const unb64uStr = (s) => new TextDecoder().decode(Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0)));

async function secreto(binding) {
  if (!binding) return null;
  return typeof binding === "string" ? binding : await binding.get();
}

async function hmac(clave, texto) {
  const k = await crypto.subtle.importKey("raw", enc.encode(clave), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64u(await crypto.subtle.sign("HMAC", k, enc.encode(texto)));
}

async function iguales(a, b) {
  // comparación en tiempo constante vía hash
  const [ha, hb] = await Promise.all([crypto.subtle.digest("SHA-256", enc.encode(a)), crypto.subtle.digest("SHA-256", enc.encode(b))]);
  const x = new Uint8Array(ha), y = new Uint8Array(hb);
  let d = 0;
  for (let i = 0; i < x.length; i++) d |= x[i] ^ y[i];
  return d === 0;
}

async function emitirToken(email, authSecret) {
  const payload = b64uStr(JSON.stringify({ email, exp: Date.now() + TOKEN_HORAS * 3600 * 1000 }));
  return `${payload}.${await hmac(authSecret, payload)}`;
}

async function verificarToken(token, authSecret) {
  if (!token || !authSecret) return null;
  const [payload, firma] = token.split(".");
  if (!payload || !firma) return null;
  if (!(await iguales(firma, await hmac(authSecret, payload)))) return null;
  try {
    const d = JSON.parse(unb64uStr(payload));
    if (!d.exp || d.exp < Date.now() || !MAILS_AUTORIZADOS.has(d.email)) return null;
    return d.email;
  } catch {
    return null;
  }
}

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

    // POST /api/login {email, password} -> {token, email, expira}
    if (request.method === "POST" && parts[0] === "api" && parts[1] === "login") {
      const authSecret = await secreto(env.AUTH_SECRET);
      const appPassword = await secreto(env.APP_PASSWORD);
      if (!authSecret || !appPassword) return json({ error: "Acceso no configurado en el Worker (faltan APP_PASSWORD / AUTH_SECRET)" }, 500);
      let b = {};
      try { b = await request.json(); } catch {}
      const email = String(b.email || "").trim().toLowerCase();
      const okMail = MAILS_AUTORIZADOS.has(email);
      const okPass = await iguales(String(b.password || ""), appPassword);
      if (!okMail || !okPass) {
        await new Promise((r) => setTimeout(r, 600)); // frena la fuerza bruta
        return json({ error: "Mail o contraseña incorrectos" }, 401);
      }
      return json({ token: await emitirToken(email, authSecret), email, expira: Date.now() + TOKEN_HORAS * 3600 * 1000 });
    }

    // Todo lo demás exige un token válido
    const authSecret = await secreto(env.AUTH_SECRET);
    const usuarioToken = await verificarToken((request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, ""), authSecret);
    if (!usuarioToken) return json({ error: "No autorizado" }, 401);

    try {
      if (!env.DATABASE_URL) {
        return json({ error: "Falta el binding DATABASE_URL en este Worker" }, 500);
      }
      const connectionString = await secreto(env.DATABASE_URL);
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

      // PUT /api/nc/:numero/documento -> guarda (o pisa) el snapshot Q.21 en R2.
      // El cliente manda el .docx ya armado como binario. Si la NC ya está
      // "congelada" (se cerró y se generó su versión final), rechaza el pisado
      // para que el registro final quede intacto para la auditoría.
      // ?congelar=1 marca esta subida como la definitiva (llamado cuando el
      // Bloque 2 pasa a estado "Cerrada").
      if (request.method === "PUT" && parts[1] === "nc" && parts[2] && parts[3] === "documento") {
        const numero = Number(parts[2]);
        if (!env.NC_DOCS) {
          return json({ error: "Falta el binding NC_DOCS (bucket R2) en este Worker" }, 500);
        }
        const [ncRow] = await sql`SELECT documento_congelado FROM nc WHERE numero = ${numero}`;
        if (!ncRow) return json({ error: "NC no encontrada" }, 404);
        if (ncRow.documento_congelado) {
          return json({ error: "El documento de esta NC ya está congelado (cerrada) y no se puede sobrescribir." }, 409);
        }
        const bytes = await request.arrayBuffer();
        const key = `nc/Q21_NC_${numero}.docx`;
        await env.NC_DOCS.put(key, bytes, {
          httpMetadata: {
            contentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
          },
        });
        const congelar = url.searchParams.get("congelar") === "1";
        await sql`
          UPDATE nc SET documento_generado_en = now(), documento_congelado = ${congelar}
          WHERE numero = ${numero}
        `;
        return json({ ok: true, congelado: congelar });
      }

      // GET /api/nc/:numero/documento -> descarga el snapshot Q.21 guardado en R2.
      // Va ANTES de la ruta genérica GET /api/nc/:numero (que no filtra parts[3]).
      if (request.method === "GET" && parts[1] === "nc" && parts[2] && parts[3] === "documento") {
        const numero = Number(parts[2]);
        if (!env.NC_DOCS) {
          return json({ error: "Falta el binding NC_DOCS (bucket R2) en este Worker" }, 500);
        }
        const key = `nc/Q21_NC_${numero}.docx`;
        const obj = await env.NC_DOCS.get(key);
        if (!obj) return json({ error: "Todavía no se generó el documento para esta NC" }, 404);
        return new Response(obj.body, {
          headers: {
            "Content-Type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "Content-Disposition": `attachment; filename="Q21_NC_${numero}.docx"`,
            ...CORS_HEADERS,
          },
        });
      }

      // GET /api/nc/proximo-numero
      // Importante: las NC migradas del histórico usan un "numero" interno sintético
      // (100001+) para no chocar entre sí, y guardan el número real de Q.11 en
      // "numero_original". El próximo correlativo tiene que seguir la numeración
      // REAL (numero_original si existe, sino numero), nunca los sintéticos.
      if (request.method === "GET" && parts[1] === "nc" && parts[2] === "proximo-numero") {
        const serieQ = SERIES[url.searchParams.get("tipo")];
        if (serieQ) {
          const [sg] = await sql`
            SELECT GREATEST(COALESCE(MAX(numero_original), 0), ${serieQ.base}) + 1 AS siguiente
            FROM nc WHERE numero >= ${serieQ.offset} AND numero < ${serieQ.offset + 100000}
          `;
          return json({ siguiente: sg.siguiente, numeroInterno: serieQ.offset + sg.siguiente });
        }
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
          WHERE numero < ${NC_MAX_INTERNO}
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
        // Clasificación (solo NC/hallazgos; las OM no se clasifican) y devolución efectiva (solo reclamos)
        const serie = serieDeTipo(b.tipo);
        const esOM = b.tipo === TIPO_OM;
        const clase = esOM ? null : b.clasificacion || (b.tipo === TIPO_HA ? "Hallazgos de Auditoría" : null);
        if (clase && !CLASES_NC.includes(clase)) return json({ error: "Clasificación inválida" }, 400);
        const conDev = clase === "Reclamos de Clientes" && typeof b.conDevolucion === "boolean" ? b.conDevolucion : null;
        let numero = b.numero;
        let numeroOriginal = null;
        if (serie) {
          // Serie propia: el cliente puede indicar el número (carga manual de OM históricas); si no, el próximo.
          let n = Number.isInteger(b.numeroSerie) && b.numeroSerie > 0 && b.numeroSerie < 100000 ? b.numeroSerie : null;
          if (n === null) {
            const [sg] = await sql`
              SELECT GREATEST(COALESCE(MAX(numero_original), 0), ${serie.base}) + 1 AS siguiente
              FROM nc WHERE numero >= ${serie.offset} AND numero < ${serie.offset + 100000}
            `;
            n = sg.siguiente;
          }
          const [dup] = await sql`SELECT numero FROM nc WHERE numero = ${serie.offset + n}`;
          if (dup) return json({ error: `Ya existe el ${esOM ? "OM" : "hallazgo"} Nº ${n}` }, 409);
          numeroOriginal = n;
          numero = serie.offset + n;
        }
        const [row] = await sql`
          INSERT INTO nc (
            numero, numero_original, tipo, categoria, cliente, producto, descripcion,
            fecha_produccion, operario, maquina, oti, cantidad_piezas,
            disposicion, fecha_programada, cumplido, fecha_cumplimiento,
            requiere_accion, creado_por,
            cargado_por_apellido, cargado_por_nombre, operario_legajo,
            clasificacion, con_devolucion
          ) VALUES (
            ${numero}, ${numeroOriginal}, ${b.tipo}, ${b.categoria}, ${b.cliente || null}, ${b.producto}, ${b.descripcion},
            ${b.fechaProduccion || null}, ${b.operario || null}, ${b.maquina || null}, ${b.oti || null}, ${b.cantidadPiezas || null},
            ${b.disposicion}, ${b.fechaProgramada || null}, ${b.cumplido || null}, ${b.fechaCumplimiento || null},
            ${b.requiereAccion || null}, ${b.usuario || null},
            ${b.cargadoPorApellido || null}, ${b.cargadoPorNombre || null}, ${b.operarioLegajo || null},
            ${clase}, ${conDev}
          )
          RETURNING *
        `;
        await sql`
          INSERT INTO nc_historial (nc_numero, campo, valor_anterior, valor_nuevo, usuario)
          VALUES (${numero}, 'creación', NULL, ${esOM ? "OM creada" : b.tipo === TIPO_HA ? "Hallazgo creado" : "NC creada"}, ${b.usuario || usuarioToken})
        `;
        return json(row, 201);
      }

      // PUT /api/nc/:numero/clasificacion {clasificacion, conDevolucion} -> Calidad confirma/corrige la clase
      if (request.method === "PUT" && parts[1] === "nc" && parts[2] && parts[3] === "clasificacion") {
        const numero = Number(parts[2]);
        const b = await request.json();
        if (!CLASES_NC.includes(b.clasificacion)) return json({ error: "Clasificación inválida" }, 400);
        const conDev = b.clasificacion === "Reclamos de Clientes" && typeof b.conDevolucion === "boolean" ? b.conDevolucion : null;
        if (b.clasificacion === "Reclamos de Clientes" && conDev === null) return json({ error: "Indicá si hubo devolución efectiva" }, 400);
        const [previo] = await sql`SELECT clasificacion, con_devolucion, tipo FROM nc WHERE numero = ${numero}`;
        if (!previo) return json({ error: "NC no encontrada" }, 404);
        if (previo.tipo === TIPO_OM) return json({ error: "Las oportunidades de mejora no se clasifican" }, 400);
        const [row] = await sql`
          UPDATE nc SET clasificacion = ${b.clasificacion}, con_devolucion = ${conDev}, actualizado_en = now()
          WHERE numero = ${numero} RETURNING *
        `;
        await sql`
          INSERT INTO nc_historial (nc_numero, campo, valor_anterior, valor_nuevo, usuario)
          VALUES (${numero}, 'clasificación',
                  ${(previo.clasificacion || "—") + (previo.con_devolucion === null ? "" : previo.con_devolucion ? " (con devolución)" : " (sin devolución)")},
                  ${b.clasificacion + (conDev === null ? "" : conDev ? " (con devolución)" : " (sin devolución)")},
                  ${b.usuario || usuarioToken})
        `;
        return json(row);
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

      // ---------------------------------------------------------------------------
      // Apéndice C (indicadores) — ver db/002_apendice_c.sql e Instructivo I.09 Rev. 012
      // ---------------------------------------------------------------------------
      const periodoCerrado = async (periodo) => {
        const anio = periodo.slice(0, 4);
        const [r] = await sql`SELECT 1 FROM apc_cierres WHERE periodo = ${periodo} OR periodo = ${anio}`;
        return !!r;
      };

      // GET /api/apc/nc-mensual -> quejas, devoluciones y fallas por mes (desde las NC de Q.21)
      if (request.method === "GET" && parts[1] === "apc" && parts[2] === "nc-mensual") {
        const rows = await sql`
          SELECT to_char(fecha_produccion, 'YYYY-MM') AS mes,
                 count(*) FILTER (WHERE clasificacion = 'Reclamos de Clientes')::int AS quejas,
                 count(*) FILTER (WHERE clasificacion = 'Reclamos de Clientes' AND con_devolucion IS TRUE)::int AS devol,
                 count(*) FILTER (WHERE clasificacion = 'Defectos x Control de Calidad')::int AS fallas
          FROM nc
          WHERE tipo <> ${TIPO_OM} AND fecha_produccion IS NOT NULL
          GROUP BY 1 ORDER BY 1
        `;
        return json(rows);
      }

      // GET /api/apc/oti -> OTI por mes ; PUT /api/apc/oti {meses:[{mes,oti_total,oti_ent,atrasos}]}
      if (parts[1] === "apc" && parts[2] === "oti") {
        if (request.method === "GET") return json(await sql`SELECT * FROM apc_oti_mensual ORDER BY mes`);
        if (request.method === "PUT") {
          const b = await request.json();
          const meses = Array.isArray(b.meses) ? b.meses : [];
          const rechazados = [];
          for (const m of meses) {
            if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(m.mes || "")) { rechazados.push({ mes: m.mes, motivo: "mes inválido" }); continue; }
            if (await periodoCerrado(m.mes)) { rechazados.push({ mes: m.mes, motivo: "período cerrado" }); continue; }
            await sql`
              INSERT INTO apc_oti_mensual (mes, oti_total, oti_ent, atrasos, fuente, actualizado_por, actualizado_en)
              VALUES (${m.mes}, ${m.oti_total | 0}, ${m.oti_ent | 0}, ${m.atrasos | 0}, ${m.fuente || null}, ${usuarioToken}, now())
              ON CONFLICT (mes) DO UPDATE SET oti_total = EXCLUDED.oti_total, oti_ent = EXCLUDED.oti_ent,
                atrasos = EXCLUDED.atrasos, fuente = EXCLUDED.fuente,
                actualizado_por = EXCLUDED.actualizado_por, actualizado_en = now()
            `;
          }
          return json({ ok: true, guardados: meses.length - rechazados.length, rechazados });
        }
      }

      // GET /api/apc/valores ; PUT /api/apc/valores {valores:[{indicador,periodo,valor,num,den,fuente}]}
      if (parts[1] === "apc" && parts[2] === "valores") {
        if (request.method === "GET") return json(await sql`SELECT * FROM apc_valores ORDER BY indicador, periodo`);
        if (request.method === "PUT") {
          const b = await request.json();
          const vals = Array.isArray(b.valores) ? b.valores : [];
          const rechazados = [];
          for (const v of vals) {
            if (!v.indicador || !/^\d{4}(-(0[1-9]|1[0-2]))?$/.test(v.periodo || "")) { rechazados.push({ indicador: v.indicador, periodo: v.periodo, motivo: "datos inválidos" }); continue; }
            if (await periodoCerrado(v.periodo)) { rechazados.push({ indicador: v.indicador, periodo: v.periodo, motivo: "período cerrado" }); continue; }
            await sql`
              INSERT INTO apc_valores (indicador, periodo, valor, num, den, fuente, actualizado_por, actualizado_en)
              VALUES (${v.indicador}, ${v.periodo}, ${v.valor ?? null}, ${v.num ?? null}, ${v.den ?? null}, ${v.fuente || null}, ${usuarioToken}, now())
              ON CONFLICT (indicador, periodo) DO UPDATE SET valor = EXCLUDED.valor, num = EXCLUDED.num, den = EXCLUDED.den,
                fuente = EXCLUDED.fuente, actualizado_por = EXCLUDED.actualizado_por, actualizado_en = now()
            `;
          }
          return json({ ok: true, guardados: vals.length - rechazados.length, rechazados });
        }
      }

      // GET /api/apc/cierres ; POST /api/apc/cierres {periodo, cerrar: true|false}
      if (parts[1] === "apc" && parts[2] === "cierres") {
        if (request.method === "GET") return json(await sql`SELECT * FROM apc_cierres ORDER BY periodo`);
        if (request.method === "POST") {
          const b = await request.json();
          if (!/^\d{4}(-(0[1-9]|1[0-2]))?$/.test(b.periodo || "")) return json({ error: "Período inválido (YYYY o YYYY-MM)" }, 400);
          if (b.cerrar === false) await sql`DELETE FROM apc_cierres WHERE periodo = ${b.periodo}`;
          else await sql`INSERT INTO apc_cierres (periodo, cerrado_por) VALUES (${b.periodo}, ${usuarioToken}) ON CONFLICT (periodo) DO NOTHING`;
          return json({ ok: true, periodo: b.periodo, cerrado: b.cerrar !== false });
        }
      }

      return json({ error: "Ruta no encontrada" }, 404);
    } catch (err) {
      return json({ error: err.message }, 500);
    }
  },
};
