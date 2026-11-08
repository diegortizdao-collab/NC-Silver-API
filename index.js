import { neon } from "@neondatabase/serverless";

// Solo las apps publicadas en GitHub Pages pueden llamar a la API desde el navegador.
const ALLOWED_ORIGIN = "https://diegortizdao-collab.github.io";
const CORS_HEADERS = {
  "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
  "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
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
  "controldecalidad@silverindustrial.com.ar",
  "controldeproducion@silverindustrial.com.ar", // sic: así lo informó el usuario
  "controldeproduccion@silverindustrial.com.ar",
  "produccion@silverindustrial.com.ar",
  "fernando@silverindustrial.com.ar", // dueño
  "hernan@silverindustrial.com.ar", // dueño
]);
// Cuentas de RRHH: solo pueden cargar el ausentismo (PUT /api/apc/valores con indicador "ausentismo").
// Usan su propia contraseña (secreto RRHH_PASSWORD), distinta de la contraseña general.
// Agregar acá el mail de Ignacio (RRHH) y crear el secreto RRHH_PASSWORD en Cloudflare.
const MAILS_RRHH = new Set([
  "rrhh@silverindustrial.com.ar", // Ignacio (RRHH)
]);
// Ausentismo por persona (datos personales): solo RRHH, Gestión de calidad y dueños. Las demás cuentas generales NO acceden.
const MAILS_PERSONAS = new Set([
  "rrhh@silverindustrial.com.ar",
  "diegortizdao@gmail.com",
  "gestioncalidad@silverindustrial.com.ar",
  "fernando@silverindustrial.com.ar",
  "hernan@silverindustrial.com.ar",
]);
// Firmas escaneadas (imágenes) para los formularios (A.14, etc.): se guardan en R2 (privado), nunca en el repo.
// Solo estas cuentas pueden verlas, subirlas o borrarlas.
const MAILS_FIRMAS = new Set([
  "diegortizdao@gmail.com",
  "gestioncalidad@silverindustrial.com.ar",
]);
// Reclamos (A.03 / A.37): ingresan con nombre completo + clave compartida (secret RECLAMOS_PASSWORD).
// Solo "edita" puede crear y modificar; los demás ven y descargan.
const RECLAMOS_USUARIOS = {
  "diego ortiz": { nombre: "Diego Ortiz", edita: true },
  "fernando nieto": { nombre: "Fernando Nieto", edita: false },
  "hernan nieto": { nombre: "Hernán Nieto", edita: false },
};
const EDITORES_RECLAMOS_MAIL = new Set(["diegortizdao@gmail.com"]); // la cuenta general de Diego también edita
const normNombre = (t) => String(t || "").normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase().replace(/\s+/g, " ").trim();
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
    if (!d.exp || d.exp < Date.now()) return null;
    if (typeof d.email === "string" && d.email.startsWith("rec:")) {
      const u = RECLAMOS_USUARIOS[normNombre(d.email.slice(4))];
      return u ? "rec:" + u.nombre : null;
    }
    if (!(MAILS_AUTORIZADOS.has(d.email) || MAILS_RRHH.has(d.email))) return null;
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


// ---- Gestión de NC: helpers ----
// Normaliza una fecha recibida (ISO o texto con año) a YYYY-MM-DD; null si vacía; undefined si no se entiende
function fechaSQL(v) {
  if (v == null || String(v).trim() === "") return null;
  const t = String(v).trim();
  const m = t.match(/^(\d{4})-(\d{2})-(\d{2})/);
  if (m) return `${m[1]}-${m[2]}-${m[3]}`;
  if (!/\d{4}/.test(t)) return undefined;
  const d = new Date(t);
  return isNaN(d) ? undefined : d.toISOString().slice(0, 10);
}
// Fecha de la base (Date de pg o texto) -> "YYYY-MM-DD" (nunca String(Date): daba "Sat May 30")
function d10(v) { if (!v) return null; return v instanceof Date ? v.toISOString().slice(0, 10) : String(v).slice(0, 10); }
function hoyAR() { return new Date(Date.now() - 3 * 3600 * 1000).toISOString().slice(0, 10); }
async function logHist(sql, numero, campo, ant, nuevo, usuario, fechaHecho, motivo) {
  await sql`INSERT INTO nc_historial (nc_numero, campo, valor_anterior, valor_nuevo, usuario, fecha_hecho, motivo)
            VALUES (${numero}, ${campo}, ${ant == null ? null : String(ant).slice(0, 300)}, ${nuevo == null ? null : String(nuevo).slice(0, 300)}, ${usuario || null}, ${fechaHecho || null}, ${motivo || null})`;
}
// Si alguna fecha del hecho es anterior a hoy, el registro es posterior al hecho: se deja constancia automática.
function motivoAuto(fechasHecho, hoy) {
  return fechasHecho.some((f) => f && d10(f) < hoy) ? "Registro posterior a la fecha del hecho" : null;
}
// Condiciones para pasar una NC a "Cerrada". Devuelve el texto del error o null.
function errorCierre(nc, an) {
  if (!nc.requiere_accion) return "Para cerrar, indicá si la NC requiere acción correctiva (Sí / No).";
  if (nc.cumplido !== "Sí" || !nc.fecha_cumplimiento) return "Para cerrar, la acción inmediata tiene que estar cumplida, con su fecha.";
  if (nc.requiere_accion === "Sí") {
    if (!an || !an.causa_raiz) return "Para cerrar una NC con acción correctiva falta la causa raíz (análisis de los 5 porqués).";
    if (!an.fecha_verif_cumplimiento || !an.evidencia_cumplimiento) return "Falta la verificación de cumplimiento de la acción (fecha y evidencia).";
    if (!an.fecha_verif_eficacia || !an.evidencia_eficacia) return "Falta la verificación de eficacia (fecha y evidencia).";
  }
  return null;
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: CORS_HEADERS });
    }

    const url = new URL(request.url);
    const parts = url.pathname.split("/").filter(Boolean); // ["api","nc", ...]

    // POST /api/reclamos/login {nombre, password} -> {token, usuario, edita}
    if (request.method === "POST" && parts[0] === "api" && parts[1] === "reclamos" && parts[2] === "login") {
      const authSecret = await secreto(env.AUTH_SECRET);
      const clave = await secreto(env.RECLAMOS_PASSWORD);
      if (!authSecret || !clave) return json({ error: "Acceso a Reclamos no configurado en el Worker (falta el secret RECLAMOS_PASSWORD)" }, 500);
      let b = {};
      try { b = await request.json(); } catch {}
      const u = RECLAMOS_USUARIOS[normNombre(b.nombre)];
      const okPass = !!u && (await iguales(String(b.password || ""), clave));
      if (!okPass) {
        await new Promise((r) => setTimeout(r, 600));
        return json({ error: "Nombre completo o contraseña incorrectos" }, 401);
      }
      return json({ token: await emitirToken("rec:" + u.nombre, authSecret), usuario: u.nombre, edita: u.edita, expira: Date.now() + TOKEN_HORAS * 3600 * 1000 });
    }

    // POST /api/login {email, password} -> {token, email, expira}
    if (request.method === "POST" && parts[0] === "api" && parts[1] === "login") {
      const authSecret = await secreto(env.AUTH_SECRET);
      const appPassword = await secreto(env.APP_PASSWORD);
      if (!authSecret || !appPassword) return json({ error: "Acceso no configurado en el Worker (faltan APP_PASSWORD / AUTH_SECRET)" }, 500);
      let b = {};
      try { b = await request.json(); } catch {}
      const email = String(b.email || "").trim().toLowerCase();
      const esRRHH = MAILS_RRHH.has(email);
      const okMail = MAILS_AUTORIZADOS.has(email) || esRRHH;
      const passEsperada = esRRHH ? await secreto(env.RRHH_PASSWORD) : appPassword;
      const okPass = !!passEsperada && (await iguales(String(b.password || ""), passEsperada));
      if (!okMail || !okPass) {
        await new Promise((r) => setTimeout(r, 600)); // frena la fuerza bruta
        return json({ error: "Mail o contraseña incorrectos" }, 401);
      }
      return json({ token: await emitirToken(email, authSecret), email, rol: esRRHH ? "rrhh" : "general", expira: Date.now() + TOKEN_HORAS * 3600 * 1000 });
    }

    // Todo lo demás exige un token válido
    const authSecret = await secreto(env.AUTH_SECRET);
    const usuarioToken = await verificarToken((request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, ""), authSecret);
    if (!usuarioToken) return json({ error: "No autorizado" }, 401);

    // Cuentas de Reclamos (nombre + clave): solo /api/reclamos/*
    if (usuarioToken.startsWith("rec:") && !(parts[0] === "api" && parts[1] === "reclamos")) {
      return json({ error: "Acceso restringido: esta cuenta solo accede a Reclamos" }, 403);
    }

    // Cuentas de RRHH: solo pueden guardar ausentismo (y nada más).
    let rrhhBody = null;
    if (MAILS_RRHH.has(usuarioToken)) {
      const enValores = parts[0] === "api" && parts[1] === "apc" && parts[2] === "valores";
      const enRRHH = parts[0] === "api" && parts[1] === "rrhh";
      if (!enRRHH && !(enValores && (request.method === "PUT" || request.method === "GET"))) return json({ error: "Acceso restringido: esta cuenta solo accede a RRHH" }, 403);
      if (!enRRHH && request.method === "PUT") {
        rrhhBody = await request.clone().json().catch(() => ({}));
        const vals = Array.isArray(rrhhBody.valores) ? rrhhBody.valores : [];
        if (!vals.length || vals.some((v) => v.indicador !== "ausentismo")) return json({ error: "Esta cuenta solo puede cargar el indicador ausentismo" }, 403);
      }
    }

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
        // Gestión de Calidad puede reemplazar el Word aun congelado (?forzar=1): edición manual con constancia en el historial.
        const forzar = url.searchParams.get("forzar") === "1" && MAILS_FIRMAS.has(usuarioToken);
        if (ncRow.documento_congelado && !forzar) {
          return json({ error: "El documento de esta NC ya está congelado (cerrada) y no se puede sobrescribir." }, 409);
        }
        const bytes = await request.arrayBuffer();
        if (forzar) {
          const u8 = new Uint8Array(bytes.slice(0, 2));
          if (u8[0] !== 0x50 || u8[1] !== 0x4b || bytes.byteLength > 15 * 1024 * 1024) return json({ error: "El archivo no es un .docx válido (o supera 15 MB)." }, 400);
        }
        const key = `nc/Q21_NC_${numero}.docx`;
        await env.NC_DOCS.put(key, bytes, {
          httpMetadata: {
            contentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
          },
        });
        if (forzar) {
          await sql`UPDATE nc SET documento_generado_en = now() WHERE numero = ${numero}`;
          await logHist(sql, numero, "documento Q.21", null, "Word reemplazado manualmente" + (ncRow.documento_congelado ? " (documento congelado)" : ""), usuarioToken, null, url.searchParams.get("motivo") || "Edición manual del Word por Gestión de Calidad");
          return json({ ok: true, congelado: !!ncRow.documento_congelado });
        }
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
        const historial = await sql`SELECT id, campo, valor_anterior, valor_nuevo, usuario, fecha, fecha_hecho, motivo FROM nc_historial WHERE nc_numero = ${numero} ORDER BY fecha DESC, id DESC`;
        const [om] = await sql`SELECT * FROM om WHERE nc_numero = ${numero}`;
        return json({ ...nc, analisis: analisis || null, notificaciones, historial, om: om || null });
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

      // PUT /api/nc/:numero/gestion -> gestión del estado de una NC desde el Q.21.
      // Cuerpo: {requiereAccion?: "Sí"|"No", cumplido?: "Sí"|"No", fechaCumplimiento?, estado?, motivo?}
      // La fecha del hecho la carga el usuario (no puede ser futura); la fecha de registro la pone el servidor.
      if (request.method === "PUT" && parts[1] === "nc" && parts[2] && parts[3] === "gestion") {
        const numero = Number(parts[2]);
        const b = await request.json();
        const [nc] = await sql`SELECT * FROM nc WHERE numero = ${numero}`;
        if (!nc) return json({ error: "NC no encontrada" }, 404);
        if (nc.documento_congelado) return json({ error: "La NC está cerrada: su documento está congelado y no se puede modificar." }, 409);
        const [an] = await sql`SELECT * FROM nc_analisis WHERE nc_numero = ${numero}`;
        const hoy = hoyAR();
        const requiere = b.requiereAccion !== undefined ? b.requiereAccion : nc.requiere_accion;
        const cumplido = b.cumplido !== undefined ? b.cumplido : nc.cumplido;
        const fechaCump = cumplido === "Sí" ? (b.fechaCumplimiento !== undefined ? d10(b.fechaCumplimiento) : d10(nc.fecha_cumplimiento)) : null;
        const estadoNuevo = b.estado || (an && an.estado) || "Abierta";
        if (requiere && !["Sí", "No"].includes(requiere)) return json({ error: "«Requiere acción correctiva» debe ser Sí o No" }, 400);
        if (cumplido && !["Sí", "No"].includes(cumplido)) return json({ error: "«Cumplido» debe ser Sí o No" }, 400);
        if (fechaCump && (!/^\d{4}-\d{2}-\d{2}$/.test(fechaCump) || fechaCump > hoy)) return json({ error: "La fecha de cumplimiento es inválida o futura: tiene que ser la fecha real en que se cumplió." }, 400);
        if (cumplido === "Sí" && !fechaCump) return json({ error: "Cargá la fecha en que se cumplió la acción inmediata." }, 400);
        if (estadoNuevo === "Cerrada" && !(an && an.estado === "Cerrada")) {
          const err = errorCierre({ ...nc, requiere_accion: requiere, cumplido, fecha_cumplimiento: fechaCump }, an);
          if (err) return json({ error: err }, 400);
        }
        const motivo = b.motivo || motivoAuto([fechaCump], hoy);
        const usuario = b.usuario || usuarioToken;
        await sql`UPDATE nc SET requiere_accion = ${requiere || null}, cumplido = ${cumplido || null}, fecha_cumplimiento = ${fechaCump}, actualizado_en = now() WHERE numero = ${numero}`;
        if ((nc.requiere_accion || null) !== (requiere || null)) await logHist(sql, numero, "requiere acción correctiva", nc.requiere_accion || "—", requiere || "—", usuario, null, motivo);
        if ((nc.cumplido || null) !== (cumplido || null) || d10(nc.fecha_cumplimiento) !== fechaCump)
          await logHist(sql, numero, "acción cumplida", (nc.cumplido || "—") + (nc.fecha_cumplimiento ? " (" + d10(nc.fecha_cumplimiento) + ")" : ""), (cumplido || "—") + (fechaCump ? " (" + fechaCump + ")" : ""), usuario, fechaCump, motivo);
        if (!an) {
          await sql`INSERT INTO nc_analisis (nc_numero, estado, no_requiere_notificacion, actualizado_en) VALUES (${numero}, ${estadoNuevo}, ${requiere === "No"}, now())`;
          await logHist(sql, numero, "estado", null, estadoNuevo, usuario, null, motivo);
        } else if (an.estado !== estadoNuevo) {
          await sql`UPDATE nc_analisis SET estado = ${estadoNuevo}, actualizado_en = now() WHERE nc_numero = ${numero}`;
          await logHist(sql, numero, "estado", an.estado, estadoNuevo, usuario, estadoNuevo === "Cerrada" ? hoy : null, motivo);
        }
        const [fila] = await sql`SELECT * FROM nc WHERE numero = ${numero}`;
        return json({ ...fila, estado: estadoNuevo });
      }

      // PUT /api/nc/:numero/datos -> completa/corrige los datos del Bloque 1 de una NC existente (p. ej. migradas del histórico).
      // Cada campo que cambia queda en el historial. Bloqueado si el documento está congelado.
      if (request.method === "PUT" && parts[1] === "nc" && parts[2] && parts[3] === "datos") {
        const numero = Number(parts[2]);
        const b = await request.json();
        const [nc] = await sql`SELECT * FROM nc WHERE numero = ${numero}`;
        if (!nc) return json({ error: "NC no encontrada" }, 404);
        if (nc.documento_congelado) return json({ error: "La NC está cerrada: su documento está congelado y no se puede modificar." }, 409);
        const txtv = (v, max = 4000) => (v == null || String(v).trim() === "" ? null : String(v).trim().slice(0, max));
        const nuevo = {
          cliente: b.cliente !== undefined ? txtv(b.cliente, 200) : nc.cliente,
          producto: b.producto !== undefined ? txtv(b.producto, 300) : nc.producto,
          descripcion: b.descripcion !== undefined ? txtv(b.descripcion) : nc.descripcion,
          operario: b.operario !== undefined ? txtv(b.operario, 200) : nc.operario,
          maquina: b.maquina !== undefined ? txtv(b.maquina, 100) : nc.maquina,
          oti: b.oti !== undefined ? txtv(b.oti, 100) : nc.oti,
          cantidad_piezas: b.cantidadPiezas !== undefined ? txtv(b.cantidadPiezas, 100) : nc.cantidad_piezas,
          disposicion: b.disposicion !== undefined ? txtv(b.disposicion) : nc.disposicion,
        };
        const fp = b.fechaProduccion !== undefined ? fechaSQL(b.fechaProduccion) : d10(nc.fecha_produccion);
        const fprog = b.fechaProgramada !== undefined ? fechaSQL(b.fechaProgramada) : d10(nc.fecha_programada);
        if (fp === undefined || fprog === undefined) return json({ error: "Una de las fechas no tiene un formato válido." }, 400);
        if (fp && fp > hoyAR()) return json({ error: "La fecha del hecho no puede ser futura." }, 400);
        const PERS = { Ortigoza: "Ramón", Canaberro: "Mariano", Ortiz: "Diego" };
        let cpAp = nc.cargado_por_apellido, cpNo = nc.cargado_por_nombre;
        if (b.cargadoPor !== undefined) {
          if (b.cargadoPor && !PERS[b.cargadoPor]) return json({ error: "«Cargada por» debe ser Ortigoza, Canaberro u Ortiz." }, 400);
          cpAp = b.cargadoPor || null; cpNo = b.cargadoPor ? PERS[b.cargadoPor] : null;
        }
        if (!nuevo.producto || !nuevo.descripcion) return json({ error: "Producto y descripción son obligatorios." }, 400);
        await sql`UPDATE nc SET cliente = ${nuevo.cliente}, producto = ${nuevo.producto}, descripcion = ${nuevo.descripcion}, operario = ${nuevo.operario},
                  maquina = ${nuevo.maquina}, oti = ${nuevo.oti}, cantidad_piezas = ${nuevo.cantidad_piezas}, disposicion = ${nuevo.disposicion},
                  fecha_produccion = ${fp}, fecha_programada = ${fprog}, cargado_por_apellido = ${cpAp}, cargado_por_nombre = ${cpNo}, actualizado_en = now()
                  WHERE numero = ${numero}`;
        const usuario = b.usuario || usuarioToken, motivo = b.motivo || "Completado de datos del registro";
        const cambios = [["cliente", nc.cliente, nuevo.cliente], ["producto", nc.producto, nuevo.producto], ["descripción", nc.descripcion, nuevo.descripcion],
          ["operario", nc.operario, nuevo.operario], ["máquina", nc.maquina, nuevo.maquina], ["OTI", nc.oti, nuevo.oti], ["cantidad de piezas", nc.cantidad_piezas, nuevo.cantidad_piezas],
          ["disposición / acción inmediata", nc.disposicion, nuevo.disposicion], ["fecha del hecho", d10(nc.fecha_produccion), fp], ["fecha programada", d10(nc.fecha_programada), fprog],
          ["cargada por", nc.cargado_por_apellido, cpAp]];
        for (const [campo, ant, nue] of cambios) if ((ant || null) !== (nue || null)) await logHist(sql, numero, "dato: " + campo, ant, nue, usuario, null, motivo);
        const [fila] = await sql`SELECT * FROM nc WHERE numero = ${numero}`;
        return json(fila);
      }

      // PUT /api/nc/:numero/cumplimiento {cumplido: "Sí"|"No", fechaCumplimiento} -> marca la disposición / acción inmediata como cumplida
      if (request.method === "PUT" && parts[1] === "nc" && parts[2] && parts[3] === "cumplimiento") {
        const numero = Number(parts[2]);
        const b = await request.json();
        if (!["Sí", "No"].includes(b.cumplido)) return json({ error: "Indicá si la acción fue cumplida (Sí / No)" }, 400);
        const fecha = b.cumplido === "Sí" ? (String(b.fechaCumplimiento || "").slice(0, 10) || null) : null;
        if (fecha && (!/^\d{4}-\d{2}-\d{2}$/.test(fecha) || fecha > hoyAR())) return json({ error: "Fecha de cumplimiento inválida o futura: tiene que ser la fecha real del hecho" }, 400);
        const [previo] = await sql`SELECT cumplido, fecha_cumplimiento, documento_congelado FROM nc WHERE numero = ${numero}`;
        if (!previo) return json({ error: "NC no encontrada" }, 404);
        if (previo.documento_congelado) return json({ error: "La NC está cerrada: su documento está congelado y no se puede modificar." }, 409);
        const [row] = await sql`
          UPDATE nc SET cumplido = ${b.cumplido}, fecha_cumplimiento = ${fecha}, actualizado_en = now()
          WHERE numero = ${numero} RETURNING *
        `;
        await sql`
          INSERT INTO nc_historial (nc_numero, campo, valor_anterior, valor_nuevo, usuario, fecha_hecho, motivo)
          VALUES (${numero}, 'acción cumplida',
                  ${(previo.cumplido || "—") + (previo.fecha_cumplimiento ? " (" + d10(previo.fecha_cumplimiento) + ")" : "")},
                  ${b.cumplido + (fecha ? " (" + fecha + ")" : "")},
                  ${b.usuario || usuarioToken}, ${fecha}, ${b.motivo || motivoAuto([fecha], hoyAR())})
        `;
        return json(row);
      }

      // PUT /api/nc/:numero/analisis -> crea o actualiza el Bloque 2
      if (request.method === "PUT" && parts[1] === "nc" && parts[2] && parts[3] === "analisis") {
        const numero = Number(parts[2]);
        const b = await request.json();
        for (const [k, rot] of [["fechaProgramadaAccion", "programada de la acción"], ["fechaVerifCumplimiento", "de verificación de cumplimiento"], ["fechaVerifEficacia", "de verificación de eficacia"]]) {
          const n = fechaSQL(b[k]);
          if (n === undefined) return json({ error: `La fecha ${rot} no tiene un formato válido (${String(b[k]).slice(0, 30)}). Volvé a elegirla en el calendario.` }, 400);
          b[k] = n;
        }

        const [previo] = await sql`SELECT * FROM nc_analisis WHERE nc_numero = ${numero}`;
        const hoy = hoyAR();
        for (const [k, rot] of [["fechaVerifCumplimiento", "verificación de cumplimiento"], ["fechaVerifEficacia", "verificación de eficacia"]]) {
          if (b[k] && (!/^\d{4}-\d{2}-\d{2}/.test(b[k]) || String(b[k]).slice(0, 10) > hoy)) return json({ error: `La fecha de ${rot} es inválida o futura: tiene que ser la fecha real del hecho.` }, 400);
        }
        const [ncPrev] = await sql`SELECT * FROM nc WHERE numero = ${numero}`;
        if (b.estado === "Cerrada" && !(previo && previo.estado === "Cerrada") && ncPrev) {
          const err = errorCierre(ncPrev, {
            causa_raiz: b.causaRaiz, fecha_verif_cumplimiento: b.fechaVerifCumplimiento, evidencia_cumplimiento: b.evidenciaCumplimiento,
            fecha_verif_eficacia: b.fechaVerifEficacia, evidencia_eficacia: b.evidenciaEficacia,
          });
          if (err) return json({ error: err }, 400);
        }

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

        const usuarioH = b.usuario || usuarioToken;
        const d10a = d10;
        const motivoA = b.motivo || motivoAuto([d10a(row.fecha_verif_cumplimiento) !== d10a(previo && previo.fecha_verif_cumplimiento) ? row.fecha_verif_cumplimiento : null, d10a(row.fecha_verif_eficacia) !== d10a(previo && previo.fecha_verif_eficacia) ? row.fecha_verif_eficacia : null], hoy);
        if (!previo || previo.estado !== row.estado) await logHist(sql, numero, "estado", previo ? previo.estado : null, row.estado, usuarioH, row.estado === "Cerrada" ? hoy : null, motivoA);
        for (const [campo, col, esFecha] of [
          ["fecha programada de la acción", "fecha_programada_accion", true], ["fecha verificación de cumplimiento", "fecha_verif_cumplimiento", true],
          ["fecha verificación de eficacia", "fecha_verif_eficacia", true], ["causa raíz", "causa_raiz", false],
          ["acción correctiva definida", "accion_descripcion", false], ["evidencia de cumplimiento", "evidencia_cumplimiento", false], ["evidencia de eficacia", "evidencia_eficacia", false],
        ]) {
          const ant = esFecha ? d10a(previo && previo[col]) : (previo && previo[col]) || null;
          const nue = esFecha ? d10a(row[col]) : row[col] || null;
          if ((ant || null) !== (nue || null)) await logHist(sql, numero, campo, ant, nue, usuarioH, esFecha && col !== "fecha_programada_accion" ? nue : null, motivoA);
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
      // Reclamos (A.03 registro + A.37 informe). Ver db/005_reclamos.sql
      //  GET  /api/reclamos/yo | GET /api/reclamos | GET /api/reclamos/proximo | GET /api/reclamos/nc-pendientes
      //  POST /api/reclamos | PUT /api/reclamos/importar | PUT /api/reclamos/:numero
      //  GET/PUT /api/reclamos/:numero/a37 (Word original en R2) | GET /api/reclamos/:numero/historial
      // Ver y descargar: cualquier cuenta con acceso. Crear/editar/importar: solo quien "edita" (Diego Ortiz).
      // ---------------------------------------------------------------------------
      if (parts[1] === "reclamos") {
        const esRec = usuarioToken.startsWith("rec:");
        const quien = esRec ? usuarioToken.slice(4) : usuarioToken;
        const edita = esRec ? !!RECLAMOS_USUARIOS[normNombre(quien)]?.edita : EDITORES_RECLAMOS_MAIL.has(usuarioToken);
        const sinPermiso = () => json({ error: "Solo Diego Ortiz puede crear o modificar reclamos" }, 403);
        const reNumero = /^\d{1,5}(-[a-z])?$/i;
        const txt = (v, max = 4000) => (v == null || String(v).trim() === "" ? null : String(v).trim().slice(0, max));
        const tri = (v) => (v === true || v === false ? v : null);
        const claveA37 = (n) => `reclamos/a37/${n}.docx`;
        // Valida y normaliza un reclamo; devuelve {error} o {r}
        const limpiar = (b, parcial = false) => {
          const r = {};
          if (!parcial || "numero" in b) {
            const n = String(b.numero ?? "").trim().toLowerCase();
            if (!reNumero.test(n)) return { error: `Número inválido: "${b.numero}"` };
            r.numero = n;
            r.num = parseInt(n, 10);
          }
          if (!parcial || "fecha" in b) {
            if (!/^\d{4}-\d{2}-\d{2}$/.test(String(b.fecha || "")) || isNaN(Date.parse(b.fecha))) return { error: `Fecha inválida en el reclamo ${b.numero ?? ""}` };
            r.fecha = b.fecha;
          }
          if (!parcial || "cliente" in b) { r.cliente = txt(b.cliente, 200); if (!r.cliente) return { error: `Falta el cliente en el reclamo ${b.numero ?? ""}` }; }
          if (!parcial || "motivo" in b) { r.motivo = txt(b.motivo, 4000); if (!r.motivo) return { error: `Falta el motivo en el reclamo ${b.numero ?? ""}` }; }
          if (!parcial || "tipo" in b) { r.tipo = b.tipo === "Proveedor" ? "Proveedor" : "Cliente"; }
          for (const [k, max] of [["oti", 120], ["producto", 300], ["cantidad", 120], ["accion_inmediata", 4000], ["observaciones", 4000], ["medio", 200], ["cant_devuelta", 300]]) {
            if (!parcial || k in b) r[k] = txt(b[k], max);
          }
          for (const k of ["pertinente", "significativo", "devolucion"]) if (!parcial || k in b) r[k] = tri(b[k]);
          if (!parcial || "nc_numeros" in b) {
            r.nc_numeros = [...new Set((Array.isArray(b.nc_numeros) ? b.nc_numeros : []).map(Number).filter((x) => Number.isInteger(x) && x > 0 && x < 100000))].slice(0, 30);
          }
          if (!parcial || "a37" in b) {
            const a = b.a37 && typeof b.a37 === "object" && !Array.isArray(b.a37) ? b.a37 : {};
            if (JSON.stringify(a).length > 30000) return { error: "El A.37 es demasiado grande" };
            r.a37 = a;
          }
          return { r };
        };

        if (request.method === "GET" && parts[2] === "yo") return json({ usuario: quien, edita });

        if (request.method === "GET" && !parts[2]) {
          const rows = await sql`SELECT * FROM reclamos ORDER BY num DESC, numero DESC`;
          return json(rows);
        }

        if (request.method === "GET" && parts[2] === "proximo") {
          const [x] = await sql`SELECT GREATEST(COALESCE(MAX(num), 0), 593) + 1 AS siguiente FROM reclamos`;
          return json({ numero: String(x.siguiente) });
        }

        // NC de reclamos (clientes o proveedores) que todavía no están vinculadas a ningún reclamo del A.03
        if (request.method === "GET" && parts[2] === "nc-pendientes") {
          const rows = await sql`
            SELECT COALESCE(n.numero_original, n.numero) AS nc, n.cliente, n.producto, n.descripcion, n.oti,
                   n.cantidad_piezas, n.clasificacion, n.con_devolucion, n.fecha_produccion AS fecha, n.creado_en
            FROM nc n
            WHERE n.clasificacion IN ('Reclamos de Clientes', 'Proveedores')
              AND NOT EXISTS (SELECT 1 FROM reclamos r WHERE COALESCE(n.numero_original, n.numero) = ANY (r.nc_numeros))
            ORDER BY n.fecha_produccion DESC NULLS LAST, 1 DESC
            LIMIT 400
          `;
          return json(rows);
        }

        if (request.method === "POST" && !parts[2]) {
          if (!edita) return sinPermiso();
          const b = await request.json().catch(() => ({}));
          if (!b.numero) {
            const [x] = await sql`SELECT GREATEST(COALESCE(MAX(num), 0), 593) + 1 AS siguiente FROM reclamos`;
            b.numero = String(x.siguiente);
          }
          const { r, error } = limpiar(b);
          if (error) return json({ error }, 400);
          const [dup] = await sql`SELECT numero FROM reclamos WHERE numero = ${r.numero}`;
          if (dup) return json({ error: `Ya existe el reclamo Nº ${r.numero}` }, 409);
          const [row] = await sql`
            INSERT INTO reclamos (numero, num, fecha, cliente, tipo, oti, producto, cantidad, motivo, pertinente, significativo,
              accion_inmediata, observaciones, medio, devolucion, cant_devuelta, nc_numeros, a37, creado_por, actualizado_por)
            VALUES (${r.numero}, ${r.num}, ${r.fecha}, ${r.cliente}, ${r.tipo}, ${r.oti}, ${r.producto}, ${r.cantidad}, ${r.motivo},
              ${r.pertinente}, ${r.significativo}, ${r.accion_inmediata}, ${r.observaciones}, ${r.medio}, ${r.devolucion},
              ${r.cant_devuelta}, ${r.nc_numeros}, ${JSON.stringify(r.a37)}::jsonb, ${quien}, ${quien})
            RETURNING *`;
          await sql`INSERT INTO reclamos_historial (numero, campo, antes, despues, usuario) VALUES (${r.numero}, 'creación', NULL, 'Reclamo creado', ${quien})`;
          return json(row, 201);
        }

        // PUT /api/reclamos/importar {reclamos:[...], sobrescribir?:bool} -> una sola consulta (límite de subrequests de Cloudflare)
        if (request.method === "PUT" && parts[2] === "importar") {
          if (!edita) return sinPermiso();
          const b = await request.json().catch(() => ({}));
          const lista = Array.isArray(b.reclamos) ? b.reclamos : [];
          if (!lista.length) return json({ error: "No hay reclamos para importar" }, 400);
          if (lista.length > 700) return json({ error: "Demasiados reclamos en un pedido (máx. 700)" }, 400);
          const validos = [], rechazados = [];
          for (const x of lista) {
            const { r, error } = limpiar(x);
            if (error) rechazados.push({ numero: x && x.numero, error });
            else validos.push({ ...r, a37: undefined });
          }
          if (!validos.length) return json({ guardados: 0, rechazados }, 200);
          const js = JSON.stringify(validos);
          const filas = b.sobrescribir
            ? await sql`
              INSERT INTO reclamos (numero, num, fecha, cliente, tipo, oti, producto, cantidad, motivo, pertinente, significativo,
                accion_inmediata, observaciones, medio, devolucion, cant_devuelta, nc_numeros, creado_por, actualizado_por)
              SELECT x.numero, x.num, x.fecha::date, x.cliente, x.tipo, x.oti, x.producto, x.cantidad, x.motivo, x.pertinente, x.significativo,
                     x.accion_inmediata, x.observaciones, x.medio, x.devolucion, x.cant_devuelta, COALESCE(x.nc_numeros, '{}'), ${quien}, ${quien}
              FROM jsonb_to_recordset(${js}::jsonb) AS x(numero text, num int, fecha text, cliente text, tipo text, oti text, producto text,
                   cantidad text, motivo text, pertinente boolean, significativo boolean, accion_inmediata text, observaciones text,
                   medio text, devolucion boolean, cant_devuelta text, nc_numeros int[])
              ON CONFLICT (numero) DO UPDATE SET fecha = EXCLUDED.fecha, cliente = EXCLUDED.cliente, tipo = EXCLUDED.tipo, oti = EXCLUDED.oti,
                producto = EXCLUDED.producto, cantidad = EXCLUDED.cantidad, motivo = EXCLUDED.motivo, pertinente = EXCLUDED.pertinente,
                significativo = EXCLUDED.significativo, accion_inmediata = EXCLUDED.accion_inmediata, observaciones = EXCLUDED.observaciones,
                medio = EXCLUDED.medio, devolucion = EXCLUDED.devolucion, cant_devuelta = EXCLUDED.cant_devuelta,
                nc_numeros = EXCLUDED.nc_numeros, actualizado_por = ${quien}, actualizado_en = now()
              RETURNING numero, (xmax = 0) AS nuevo`
            : await sql`
              INSERT INTO reclamos (numero, num, fecha, cliente, tipo, oti, producto, cantidad, motivo, pertinente, significativo,
                accion_inmediata, observaciones, medio, devolucion, cant_devuelta, nc_numeros, creado_por, actualizado_por)
              SELECT x.numero, x.num, x.fecha::date, x.cliente, x.tipo, x.oti, x.producto, x.cantidad, x.motivo, x.pertinente, x.significativo,
                     x.accion_inmediata, x.observaciones, x.medio, x.devolucion, x.cant_devuelta, COALESCE(x.nc_numeros, '{}'), ${quien}, ${quien}
              FROM jsonb_to_recordset(${js}::jsonb) AS x(numero text, num int, fecha text, cliente text, tipo text, oti text, producto text,
                   cantidad text, motivo text, pertinente boolean, significativo boolean, accion_inmediata text, observaciones text,
                   medio text, devolucion boolean, cant_devuelta text, nc_numeros int[])
              ON CONFLICT (numero) DO NOTHING
              RETURNING numero, true AS nuevo`;
          return json({ guardados: filas.length, nuevos: filas.filter((f) => f.nuevo).length, existentes: validos.length - filas.length, rechazados });
        }

        const numero = String(parts[2] || "").toLowerCase();
        if (!reNumero.test(numero)) return json({ error: "Número de reclamo inválido" }, 400);

        // A.37 Word original (histórico) en R2
        if (parts[3] === "a37") {
          if (!env.NC_DOCS) return json({ error: "Falta el binding R2 NC_DOCS" }, 500);
          if (request.method === "GET") {
            const obj = await env.NC_DOCS.get(claveA37(numero));
            if (!obj) return json({ error: "Este reclamo no tiene un A.37 guardado" }, 404);
            return new Response(obj.body, { headers: { "Content-Type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "Cache-Control": "private, no-store", ...CORS_HEADERS } });
          }
          if (request.method === "PUT") {
            if (!edita) return sinPermiso();
            const bytes = new Uint8Array(await request.arrayBuffer());
            if (bytes.length < 1000 || bytes.length > 4 * 1024 * 1024) return json({ error: "El archivo debe pesar menos de 4 MB" }, 400);
            if (!(bytes[0] === 0x50 && bytes[1] === 0x4b)) return json({ error: "No es un .docx válido" }, 400);
            const [ex] = await sql`SELECT numero FROM reclamos WHERE numero = ${numero}`;
            if (!ex) return json({ error: `El reclamo ${numero} no existe: importá primero el A.03` }, 404);
            await env.NC_DOCS.put(claveA37(numero), bytes, { httpMetadata: { contentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document" }, customMetadata: { subido_por: quien } });
            await sql`UPDATE reclamos SET a37_key = ${claveA37(numero)}, a37_origen = 'original', actualizado_por = ${quien}, actualizado_en = now() WHERE numero = ${numero}`;
            await sql`INSERT INTO reclamos_historial (numero, campo, antes, despues, usuario) VALUES (${numero}, 'A.37', NULL, 'Word original guardado', ${quien})`;
            return json({ ok: true, numero, bytes: bytes.length });
          }
        }

        if (request.method === "GET" && parts[3] === "historial") {
          return json(await sql`SELECT campo, antes, despues, usuario, fecha FROM reclamos_historial WHERE numero = ${numero} ORDER BY id DESC LIMIT 200`);
        }

        if (request.method === "GET" && !parts[3]) {
          const [row] = await sql`SELECT * FROM reclamos WHERE numero = ${numero}`;
          return row ? json(row) : json({ error: "No existe ese reclamo" }, 404);
        }

        if (request.method === "PUT" && !parts[3]) {
          if (!edita) return sinPermiso();
          const b = await request.json().catch(() => ({}));
          delete b.numero;
          const { r, error } = limpiar(b, true);
          if (error) return json({ error }, 400);
          const [prev] = await sql`SELECT * FROM reclamos WHERE numero = ${numero}`;
          if (!prev) return json({ error: "No existe ese reclamo" }, 404);
          const m = { ...prev, ...r };
          const [row] = await sql`
            UPDATE reclamos SET fecha = ${m.fecha}, cliente = ${m.cliente}, tipo = ${m.tipo}, oti = ${m.oti}, producto = ${m.producto},
              cantidad = ${m.cantidad}, motivo = ${m.motivo}, pertinente = ${m.pertinente}, significativo = ${m.significativo},
              accion_inmediata = ${m.accion_inmediata}, observaciones = ${m.observaciones}, medio = ${m.medio}, devolucion = ${m.devolucion},
              cant_devuelta = ${m.cant_devuelta}, nc_numeros = ${m.nc_numeros}, a37 = ${JSON.stringify(m.a37 || {})}::jsonb,
              actualizado_por = ${quien}, actualizado_en = now()
            WHERE numero = ${numero} RETURNING *`;
          const norm = (v) => (v instanceof Date ? v.toISOString().slice(0, 10) : v == null ? null : typeof v === "object" ? JSON.stringify(v).slice(0, 500) : String(v).slice(0, 500));
          const cambios = Object.keys(r).filter((k) => norm(prev[k]) !== norm(r[k]));
          for (const k of cambios.slice(0, 20)) {
            await sql`INSERT INTO reclamos_historial (numero, campo, antes, despues, usuario) VALUES (${numero}, ${k}, ${norm(prev[k])}, ${norm(r[k])}, ${quien})`;
          }
          return json(row);
        }

        return json({ error: "Ruta de reclamos no encontrada" }, 404);
      }

      // ---------------------------------------------------------------------------
      // Firmas (R2, privado): GET /api/firmas -> lista ; GET /api/firmas/:id -> PNG ;
      // PUT /api/firmas/:id?nombre=... (cuerpo = PNG) ; DELETE /api/firmas/:id
      // ---------------------------------------------------------------------------
      if (parts[1] === "firmas") {
        if (!MAILS_FIRMAS.has(usuarioToken)) return json({ error: "Acceso restringido: las firmas solo las gestiona Gestión de calidad" }, 403);
        if (!env.NC_DOCS) return json({ error: "Falta el binding NC_DOCS (bucket R2) en este Worker" }, 500);
        const id = parts[2];
        if (!id) {
          if (request.method !== "GET") return json({ error: "Método no permitido" }, 405);
          const lista = await env.NC_DOCS.list({ prefix: "firmas/", include: ["customMetadata"] });
          return json(lista.objects.map((o) => ({
            id: o.key.slice("firmas/".length).replace(/\.png$/, ""),
            nombre: (o.customMetadata && o.customMetadata.nombre) || o.key,
            bytes: o.size,
            subida: o.uploaded,
          })));
        }
        if (!/^[a-z0-9-]{2,40}$/.test(id)) return json({ error: "Identificador de firma inválido (minúsculas, números y guiones)" }, 400);
        const key = `firmas/${id}.png`;
        if (request.method === "GET") {
          const obj = await env.NC_DOCS.get(key);
          if (!obj) return json({ error: "Firma no encontrada" }, 404);
          return new Response(obj.body, { headers: { "Content-Type": "image/png", "Cache-Control": "private, no-store", ...CORS_HEADERS } });
        }
        if (request.method === "PUT") {
          const bytes = await request.arrayBuffer();
          const b = new Uint8Array(bytes);
          const png = b.length > 24 && b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47;
          if (!png) return json({ error: "El archivo debe ser una imagen PNG" }, 400);
          if (b.length > 600 * 1024) return json({ error: "La imagen es demasiado grande (máximo 600 KB)" }, 413);
          const nombre = (url.searchParams.get("nombre") || id).slice(0, 80);
          await env.NC_DOCS.put(key, bytes, { httpMetadata: { contentType: "image/png" }, customMetadata: { nombre, subido_por: usuarioToken } });
          return json({ ok: true, id, nombre });
        }
        if (request.method === "DELETE") {
          await env.NC_DOCS.delete(key);
          return json({ ok: true });
        }
        return json({ error: "Método no permitido" }, 405);
      }

      // GET /api/om -> registro Q.25 de oportunidades de mejora (une om con los
      // datos del Q.21 de origen: fecha, descripción y si ya tiene Word en R2).
      if (request.method === "GET" && parts[1] === "om" && !parts[2]) {
        const rows = await sql`
          SELECT o.*, n.numero_original, n.fecha_produccion, n.descripcion, n.producto,
                 n.documento_generado_en, n.cargado_por_apellido
          FROM om o
          JOIN nc n ON n.numero = o.nc_numero
          ORDER BY COALESCE(n.numero_original, n.numero) DESC
        `;
        return json(rows);
      }

      // POST /api/om/historica -> carga una OM anterior a esta app. Crea un Q.21
      // mínimo (numero interno sintético >=100000, numero_original = el real,
      // fecha propia) y su fila Q.25. Después se le puede subir el Word histórico
      // desde la pestaña "Cargar Word históricos" del dashboard.
      if (request.method === "POST" && parts[1] === "om" && parts[2] === "historica") {
        const b = await request.json();
        const orig = Number(b.numeroOriginal);
        if (!orig || !b.descripcion) return json({ error: "Faltan número y descripción" }, 400);
        const [dup] = await sql`SELECT numero FROM nc WHERE COALESCE(numero_original, numero) = ${orig} AND tipo = 'Op. de mejora'`;
        if (dup && !b.actualizar) return json({ error: `Ya existe la OM Nº ${orig}` }, 409);
        let interno;
        if (dup) {
          // Reedición por Excel: se completan datos de una OM ya cargada
          interno = dup.numero;
          await sql`
            UPDATE nc SET descripcion = ${b.descripcion},
                          fecha_produccion = COALESCE(${b.fecha || null}, fecha_produccion),
                          producto = COALESCE(NULLIF(${b.producto || ""}, ''), producto),
                          actualizado_en = now()
            WHERE numero = ${interno}
          `;
        } else {
          const [mx] = await sql`SELECT COALESCE(MAX(numero) FILTER (WHERE numero >= 100000), 100000) AS m FROM nc`;
          interno = Number(mx.m) + 1;
          await sql`
            INSERT INTO nc (numero, numero_original, tipo, categoria, producto, descripcion,
                            fecha_produccion, disposicion, creado_por)
            VALUES (${interno}, ${orig}, 'Op. de mejora', 'Otros', ${b.producto || "—"}, ${b.descripcion},
                    ${b.fecha || null}, 'N/A (oportunidad de mejora)', 'Carga histórica Q.25')
          `;
        }
        const [row] = await sql`
          INSERT INTO om (nc_numero, origen, proponente, responsable, fecha_prevista,
                          beneficio_esperado, estado, vigencia, fecha_vigencia, actualizado_en)
          VALUES (${interno}, ${b.origen || null}, ${b.proponente || null}, ${b.responsable || null},
                  ${b.fechaPrevista || null}, ${b.beneficioEsperado || null}, ${b.estado || null},
                  ${b.vigencia || "Sí"}, ${b.fechaVigencia || null}, now())
          ON CONFLICT (nc_numero) DO UPDATE SET
            origen = COALESCE(EXCLUDED.origen, om.origen),
            proponente = COALESCE(EXCLUDED.proponente, om.proponente),
            responsable = COALESCE(EXCLUDED.responsable, om.responsable),
            fecha_prevista = COALESCE(EXCLUDED.fecha_prevista, om.fecha_prevista),
            beneficio_esperado = COALESCE(EXCLUDED.beneficio_esperado, om.beneficio_esperado),
            estado = COALESCE(EXCLUDED.estado, om.estado),
            fecha_vigencia = COALESCE(EXCLUDED.fecha_vigencia, om.fecha_vigencia),
            vigencia = COALESCE(${b.vigencia || null}, om.vigencia),
            actualizado_en = now()
          RETURNING *
        `;
        return json(row, 201);
      }

      // PUT /api/om/:numero/gestion -> ciclo de vida de la OM (Q.21.B): aprobación, plan, implementación y
      // verificación de vigencia a los 6 meses. Solo toca los campos que vienen en el cuerpo.
      // Cierre: implementada con evidencia + verificación de vigencia con fecha >= implementación + 6 meses y "sigue vigente".
      if (request.method === "PUT" && parts[1] === "om" && parts[2] && parts[3] === "gestion") {
        const numero = Number(parts[2]);
        const b = await request.json();
        const [nc] = await sql`SELECT numero, documento_congelado FROM nc WHERE numero = ${numero} AND tipo = ${TIPO_OM}`;
        if (!nc) return json({ error: "OM no encontrada" }, 404);
        if (nc.documento_congelado) return json({ error: "La OM está cerrada: su documento está congelado y no se puede modificar." }, 409);
        const [prev] = await sql`SELECT * FROM om WHERE nc_numero = ${numero}`;
        const hoy = hoyAR();
        const pick = (k, col) => (b[k] !== undefined ? (b[k] === "" ? null : b[k]) : prev ? prev[col] : null);
        const f = {
          aprobada: pick("aprobada", "aprobada"), necesidad: pick("necesidad", "necesidad"), impacto: pick("impacto", "impacto"), meta: pick("meta", "meta"),
          plan: pick("plan", "plan"), origen: pick("origen", "origen"), proponente: pick("proponente", "proponente"), responsable: pick("responsable", "responsable"),
          fecha_prevista: d10(pick("fechaPrevista", "fecha_prevista")), beneficio_esperado: pick("beneficioEsperado", "beneficio_esperado"),
          fecha_implementacion: d10(pick("fechaImplementacion", "fecha_implementacion")),
          fecha_verif_implementacion: d10(pick("fechaVerifImplementacion", "fecha_verif_implementacion")),
          evidencia_implementacion: pick("evidenciaImplementacion", "evidencia_implementacion"),
          vigencia: pick("vigencia", "vigencia"), fecha_vigencia: d10(pick("fechaVigencia", "fecha_vigencia")), evidencia_vigencia: pick("evidenciaVigencia", "evidencia_vigencia"),
          estado: pick("estado", "estado"),
        };
        for (const [k, rot] of [["fecha_implementacion", "implementación"], ["fecha_verif_implementacion", "verificación de la implementación"], ["fecha_vigencia", "verificación de vigencia"]]) {
          if (f[k] && (!/^\d{4}-\d{2}-\d{2}$/.test(f[k]) || f[k] > hoy)) return json({ error: `La fecha de ${rot} es inválida o futura: tiene que ser la fecha real del hecho.` }, 400);
        }
        let cerradaEn = prev ? d10(prev.cerrada_en) : null, motivoCierre = prev ? prev.motivo_cierre : null;
        if (b.cerrar) {
          if (f.aprobada !== "Sí") return json({ error: "Para cerrar la OM, tiene que estar aprobada (Sí)." }, 400);
          if (!f.fecha_implementacion || !f.evidencia_implementacion) return json({ error: "Para cerrar la OM falta la implementación (fecha y evidencia)." }, 400);
          if (!f.fecha_vigencia || !f.evidencia_vigencia) return json({ error: "Para cerrar la OM falta la verificación de vigencia a los 6 meses (fecha y evidencia)." }, 400);
          const minimo = new Date(f.fecha_implementacion + "T00:00:00Z"); minimo.setUTCMonth(minimo.getUTCMonth() + 6);
          if (f.fecha_vigencia < minimo.toISOString().slice(0, 10)) return json({ error: `La verificación de vigencia tiene que ser a los 6 meses o más de la implementación (desde el ${minimo.toISOString().slice(0, 10)}).` }, 400);
          if (f.vigencia !== "Sí") return json({ error: "Para cerrar, la mejora tiene que seguir implementada (vigencia = Sí). Si dejó de aplicarse, reabrila o discontinuala." }, 400);
          cerradaEn = hoy; motivoCierre = "Mejora implementada y vigente a los 6 meses";
        } else if (b.discontinuar) {
          if (!b.motivoCierre) return json({ error: "Indicá el motivo por el que se discontinúa la OM." }, 400);
          cerradaEn = hoy; motivoCierre = "Discontinuada: " + b.motivoCierre; f.vigencia = "No";
        } else if (b.reabrir) { cerradaEn = null; motivoCierre = null; }
        const usuario = b.usuario || usuarioToken;
        const motivo = b.motivo || motivoAuto([f.fecha_implementacion, f.fecha_verif_implementacion, f.fecha_vigencia].filter((x, i) => x && x !== d10(prev && [prev.fecha_implementacion, prev.fecha_verif_implementacion, prev.fecha_vigencia][i])), hoy);
        const [row] = await sql`
          INSERT INTO om (nc_numero, origen, proponente, responsable, fecha_prevista, beneficio_esperado, estado, vigencia, fecha_vigencia, aprobada, necesidad, impacto, meta, plan,
                          fecha_implementacion, fecha_verif_implementacion, evidencia_implementacion, evidencia_vigencia, cerrada_en, motivo_cierre, actualizado_en)
          VALUES (${numero}, ${f.origen}, ${f.proponente}, ${f.responsable}, ${f.fecha_prevista}, ${f.beneficio_esperado}, ${f.estado}, ${f.vigencia}, ${f.fecha_vigencia}, ${f.aprobada}, ${f.necesidad}, ${f.impacto}, ${f.meta}, ${f.plan},
                  ${f.fecha_implementacion}, ${f.fecha_verif_implementacion}, ${f.evidencia_implementacion}, ${f.evidencia_vigencia}, ${cerradaEn}, ${motivoCierre}, now())
          ON CONFLICT (nc_numero) DO UPDATE SET
            origen = EXCLUDED.origen, proponente = EXCLUDED.proponente, responsable = EXCLUDED.responsable, fecha_prevista = EXCLUDED.fecha_prevista,
            beneficio_esperado = EXCLUDED.beneficio_esperado, estado = EXCLUDED.estado, vigencia = EXCLUDED.vigencia, fecha_vigencia = EXCLUDED.fecha_vigencia,
            aprobada = EXCLUDED.aprobada, necesidad = EXCLUDED.necesidad, impacto = EXCLUDED.impacto, meta = EXCLUDED.meta, plan = EXCLUDED.plan,
            fecha_implementacion = EXCLUDED.fecha_implementacion, fecha_verif_implementacion = EXCLUDED.fecha_verif_implementacion,
            evidencia_implementacion = EXCLUDED.evidencia_implementacion, evidencia_vigencia = EXCLUDED.evidencia_vigencia,
            cerrada_en = EXCLUDED.cerrada_en, motivo_cierre = EXCLUDED.motivo_cierre, actualizado_en = now()
          RETURNING *
        `;
        const seguimiento = [
          ["aprobada", "mejora aprobada", false], ["fecha_implementacion", "fecha de implementación", true], ["fecha_verif_implementacion", "fecha verificación de implementación", true],
          ["fecha_vigencia", "fecha verificación de vigencia (6 meses)", true], ["vigencia", "sigue vigente", false], ["estado", "estado Q.25", false],
          ["necesidad", "necesidad / problema", false], ["impacto", "impacto esperado", false], ["meta", "indicador / meta", false], ["plan", "plan de implementación", false],
          ["evidencia_implementacion", "evidencia de implementación", false], ["evidencia_vigencia", "evidencia de vigencia", false],
        ];
        for (const [col, campo, esFecha] of seguimiento) {
          const ant = prev ? (esFecha ? d10(prev[col]) : prev[col]) : null, nue = esFecha ? d10(row[col]) : row[col];
          if ((ant || null) !== (nue || null)) await logHist(sql, numero, "OM · " + campo, ant, nue, usuario, esFecha ? nue : null, motivo);
        }
        const cierreAnt = prev ? d10(prev.cerrada_en) : null;
        if ((cierreAnt || null) !== (d10(row.cerrada_en) || null)) await logHist(sql, numero, "OM · cierre", cierreAnt ? "Cerrada" : "Abierta", row.cerrada_en ? row.motivo_cierre : "Reabierta", usuario, d10(row.cerrada_en), motivo);
        return json(row);
      }

      // PUT /api/om/:numero -> crea o actualiza la fila Q.25 de esa OM
      if (request.method === "PUT" && parts[1] === "om" && parts[2]) {
        const numero = Number(parts[2]);
        const b = await request.json();
        if (b.fecha || b.descripcion) {
          await sql`
            UPDATE nc SET fecha_produccion = COALESCE(${b.fecha || null}, fecha_produccion),
                          descripcion = COALESCE(NULLIF(${b.descripcion || ""}, ''), descripcion),
                          actualizado_en = now()
            WHERE numero = ${numero}
          `;
        }
        const [row] = await sql`
          INSERT INTO om (
            nc_numero, origen, proponente, responsable, fecha_prevista,
            beneficio_esperado, estado, vigencia, fecha_vigencia, actualizado_en
          ) VALUES (
            ${numero}, ${b.origen || null}, ${b.proponente || null}, ${b.responsable || null}, ${b.fechaPrevista || null},
            ${b.beneficioEsperado || null}, ${b.estado || null}, ${b.vigencia || null}, ${b.fechaVigencia || null}, now()
          )
          ON CONFLICT (nc_numero) DO UPDATE SET
            origen = EXCLUDED.origen, proponente = EXCLUDED.proponente,
            responsable = EXCLUDED.responsable, fecha_prevista = EXCLUDED.fecha_prevista,
            beneficio_esperado = EXCLUDED.beneficio_esperado, estado = EXCLUDED.estado,
            vigencia = EXCLUDED.vigencia, fecha_vigencia = EXCLUDED.fecha_vigencia,
            actualizado_en = now()
          RETURNING *
        `;
        return json(row);
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
          const cerrados = new Set((await sql`SELECT periodo FROM apc_cierres`).map((r) => r.periodo));
          const ok = [];
          for (const m of meses) {
            if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(m.mes || "")) { rechazados.push({ mes: m.mes, motivo: "mes inválido" }); continue; }
            if (cerrados.has(m.mes) || cerrados.has(m.mes.slice(0, 4))) { rechazados.push({ mes: m.mes, motivo: "período cerrado" }); continue; }
            ok.push(m);
          }
          if (ok.length) {
            await sql`
              INSERT INTO apc_oti_mensual (mes, oti_total, oti_ent, atrasos, fuente, actualizado_por, actualizado_en)
              SELECT t.mes, t.ot, t.oe, t.at, t.fu, ${usuarioToken}, now()
              FROM unnest(${ok.map((m) => m.mes)}::text[], ${ok.map((m) => m.oti_total | 0)}::int[], ${ok.map((m) => m.oti_ent | 0)}::int[], ${ok.map((m) => m.atrasos | 0)}::int[], ${ok.map((m) => m.fuente || null)}::text[]) AS t(mes, ot, oe, at, fu)
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
        if (request.method === "GET") {
          if (MAILS_RRHH.has(usuarioToken)) return json(await sql`SELECT * FROM apc_valores WHERE indicador = 'ausentismo' ORDER BY periodo`);
          return json(await sql`SELECT * FROM apc_valores ORDER BY indicador, periodo`);
        }
        if (request.method === "PUT") {
          const b = await request.json();
          const vals = Array.isArray(b.valores) ? b.valores : [];
          const rechazados = [];
          if (vals.length > 500) return json({ error: "Demasiados valores en un pedido (máximo 500)" }, 400);
          // Una sola consulta para los períodos cerrados (Cloudflare limita las consultas por pedido).
          const cerrados = new Set((await sql`SELECT periodo FROM apc_cierres`).map((r) => r.periodo));
          const ok = [];
          for (const v of vals) {
            if (!v.indicador || !/^\d{4}(-(0[1-9]|1[0-2]))?$/.test(v.periodo || "")) { rechazados.push({ indicador: v.indicador, periodo: v.periodo, motivo: "datos inválidos" }); continue; }
            if (cerrados.has(v.periodo) || cerrados.has(v.periodo.slice(0, 4))) { rechazados.push({ indicador: v.indicador, periodo: v.periodo, motivo: "período cerrado" }); continue; }
            ok.push(v);
          }
          if (ok.length) {
            await sql`
              INSERT INTO apc_valores (indicador, periodo, valor, num, den, fuente, actualizado_por, actualizado_en)
              SELECT t.i, t.p, t.v, t.n, t.d, t.f, ${usuarioToken}, now()
              FROM unnest(${ok.map((v) => v.indicador)}::text[], ${ok.map((v) => v.periodo)}::text[], ${ok.map((v) => v.valor ?? null)}::float8[], ${ok.map((v) => v.num ?? null)}::float8[], ${ok.map((v) => v.den ?? null)}::float8[], ${ok.map((v) => v.fuente || null)}::text[]) AS t(i, p, v, n, d, f)
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

      // ---------------------------------------------------------------------------
      // RRHH: personal, programa de capacitación (A.18) y registro de asistencia (A.14 / A.26)
      // Datos personales: solo cuentas de RRHH y generales. Ver db/003_rrhh_capacitacion.sql
      // ---------------------------------------------------------------------------
      const anioCerrado = async (anio) => {
        const [r] = await sql`SELECT 1 FROM apc_cierres WHERE periodo = ${String(anio)}`;
        return !!r;
      };
      const ESTADOS = ["Agendada", "Cumplida", "Reprogramada", "Cancelada"];
      const aFecha = (v) => (/^\d{4}-\d{2}-\d{2}$/.test(v || "") ? v : null);

      // GET /api/rrhh/personal ; PUT /api/rrhh/personal {personal:[{legajo,nombre,activo}]}
      if (parts[1] === "rrhh" && parts[2] === "personal") {
        if (request.method === "GET") return json(await sql`SELECT legajo, nombre, activo FROM rrhh_personal ORDER BY legajo`);
        if (request.method === "PUT") {
          const b = await request.json();
          const lista = Array.isArray(b.personal) ? b.personal : [];
          let n = 0;
          for (const p of lista) {
            const legajo = Number(p.legajo);
            if (!Number.isInteger(legajo) || !String(p.nombre || "").trim()) continue;
            await sql`
              INSERT INTO rrhh_personal (legajo, nombre, activo, actualizado_por, actualizado_en)
              VALUES (${legajo}, ${String(p.nombre).trim()}, ${p.activo !== false}, ${usuarioToken}, now())
              ON CONFLICT (legajo) DO UPDATE SET nombre = EXCLUDED.nombre, activo = EXCLUDED.activo,
                actualizado_por = EXCLUDED.actualizado_por, actualizado_en = now()`;
            n++;
          }
          return json({ ok: true, guardados: n });
        }
      }

      // GET /api/rrhh/capacitaciones?anio=2026 ; PUT /api/rrhh/capacitaciones {id?, anio, tema, ...}
      if (parts[1] === "rrhh" && parts[2] === "capacitaciones" && !parts[3]) {
        if (request.method === "GET") {
          const anio = url.searchParams.get("anio") ? Number(url.searchParams.get("anio")) : null;
          const rows = await sql`
            SELECT c.*, (SELECT count(*)::int FROM rrhh_asistencia a WHERE a.cap_id = c.id) AS asistentes
            FROM rrhh_capacitaciones c
            WHERE (${anio}::int IS NULL OR c.anio = ${anio}::int)
            ORDER BY c.anio DESC, c.fecha_real NULLS LAST, c.fecha_plan NULLS LAST, c.id`;
          return json(rows);
        }
        if (request.method === "PUT") {
          const b = await request.json();
          const anio = Number(b.anio);
          if (!Number.isInteger(anio) || anio < 2000 || !String(b.tema || "").trim()) return json({ error: "Faltan año o tema" }, 400);
          if (!ESTADOS.includes(b.estado || "Agendada")) return json({ error: "Estado inválido" }, 400);
          if (await anioCerrado(anio)) return json({ error: "El año " + anio + " está cerrado" }, 409);
          const tipo = b.tipo === "Interno" || b.tipo === "Externo" ? b.tipo : null;
          const efectiva = typeof b.efect_efectiva === "boolean" ? b.efect_efectiva : null;
          if (b.id) {
            const [row] = await sql`
              UPDATE rrhh_capacitaciones SET anio = ${anio}, tema = ${b.tema.trim()}, instructor = ${b.instructor || null}, tipo = ${tipo},
                periodo_plan = ${b.periodo_plan || null}, fecha_plan = ${aFecha(b.fecha_plan)}, destinatarios = ${b.destinatarios || null},
                lugar = ${b.lugar || null}, programada = ${b.programada !== false}, estado = ${b.estado || "Agendada"},
                fecha_real = ${aFecha(b.fecha_real)}, duracion = ${b.duracion || null}, temas = ${b.temas || null}, observaciones = ${b.observaciones || null},
                efect_fecha_programada = ${aFecha(b.efect_fecha_programada)}, efect_evaluacion = ${b.efect_evaluacion || null}, efect_efectiva = ${efectiva}, efect_fecha_real = ${aFecha(b.efect_fecha_real)},
                efect_evaluador = ${b.efect_evaluador || null}, efect_acciones = ${b.efect_acciones || null},
                actualizado_por = ${usuarioToken}, actualizado_en = now()
              WHERE id = ${Number(b.id)} RETURNING *`;
            if (!row) return json({ error: "No existe la capacitación" }, 404);
            return json(row);
          }
          const [row] = await sql`
            INSERT INTO rrhh_capacitaciones (anio, tema, instructor, tipo, periodo_plan, fecha_plan, destinatarios, lugar, programada, estado,
              fecha_real, duracion, temas, observaciones, efect_fecha_programada, efect_evaluacion, efect_efectiva, efect_fecha_real, efect_evaluador, efect_acciones, actualizado_por)
            VALUES (${anio}, ${b.tema.trim()}, ${b.instructor || null}, ${tipo}, ${b.periodo_plan || null}, ${aFecha(b.fecha_plan)}, ${b.destinatarios || null},
              ${b.lugar || null}, ${b.programada !== false}, ${b.estado || "Agendada"}, ${aFecha(b.fecha_real)}, ${b.duracion || null}, ${b.temas || null},
              ${b.observaciones || null}, ${aFecha(b.efect_fecha_programada)}, ${b.efect_evaluacion || null}, ${efectiva}, ${aFecha(b.efect_fecha_real)}, ${b.efect_evaluador || null},
              ${b.efect_acciones || null}, ${usuarioToken})
            RETURNING *`;
          return json(row, 201);
        }
      }

      // GET /api/rrhh/capacitaciones/:id -> capacitación + asistentes ; PUT /api/rrhh/capacitaciones/:id/asistencia {asistentes:[{legajo,calificacion,observaciones}]}
      if (parts[1] === "rrhh" && parts[2] === "capacitaciones" && parts[3]) {
        const id = Number(parts[3]);
        if (!Number.isInteger(id)) return json({ error: "Id inválido" }, 400);
        if (request.method === "GET" && !parts[4]) {
          const [cap] = await sql`SELECT * FROM rrhh_capacitaciones WHERE id = ${id}`;
          if (!cap) return json({ error: "No existe la capacitación" }, 404);
          const asistentes = await sql`
            SELECT a.legajo, p.nombre, a.calificacion, a.observaciones
            FROM rrhh_asistencia a JOIN rrhh_personal p ON p.legajo = a.legajo WHERE a.cap_id = ${id} ORDER BY p.nombre`;
          return json({ ...cap, asistentes });
        }
        if (request.method === "PUT" && parts[4] === "asistencia") {
          const [cap] = await sql`SELECT anio FROM rrhh_capacitaciones WHERE id = ${id}`;
          if (!cap) return json({ error: "No existe la capacitación" }, 404);
          if (await anioCerrado(cap.anio)) return json({ error: "El año " + cap.anio + " está cerrado" }, 409);
          const b = await request.json();
          const lista = Array.isArray(b.asistentes) ? b.asistentes : [];
          await sql`DELETE FROM rrhh_asistencia WHERE cap_id = ${id}`;
          let n = 0;
          for (const a of lista) {
            const legajo = Number(a.legajo);
            if (!Number.isInteger(legajo)) continue;
            const cal = ["S", "PS", "NS"].includes(a.calificacion) ? a.calificacion : null;
            await sql`INSERT INTO rrhh_asistencia (cap_id, legajo, calificacion, observaciones) VALUES (${id}, ${legajo}, ${cal}, ${a.observaciones || null}) ON CONFLICT DO NOTHING`;
            n++;
          }
          await sql`UPDATE rrhh_capacitaciones SET actualizado_por = ${usuarioToken}, actualizado_en = now() WHERE id = ${id}`;
          return json({ ok: true, asistentes: n });
        }
      }

      // ---- Ausentismo por persona y por mes (datos personales: ver MAILS_PERSONAS) ----
      // GET /api/rrhh/aus-personas?desde=YYYY-MM&hasta=YYYY-MM -> [{periodo,legajo,codigos:[...],laborables}]
      // PUT /api/rrhh/aus-personas {periodo, filas:[{legajo,codigos:[...],laborables}]}
      if (parts[1] === "rrhh" && parts[2] === "aus-personas") {
        if (!MAILS_PERSONAS.has(usuarioToken)) return json({ error: "Sin permiso para ver o cargar el ausentismo por persona" }, 403);
        const reMes = /^\d{4}-(0[1-9]|1[0-2])$/;
        if (request.method === "GET") {
          const desde = reMes.test(url.searchParams.get("desde") || "") ? url.searchParams.get("desde") : "0000-01";
          const hasta = reMes.test(url.searchParams.get("hasta") || "") ? url.searchParams.get("hasta") : "9999-12";
          const rows = await sql`SELECT periodo, legajo, codigos, laborables FROM rrhh_aus_mes WHERE periodo >= ${desde} AND periodo <= ${hasta} ORDER BY periodo, legajo`;
          return json(rows.map((r) => ({ ...r, codigos: String(r.codigos).split("|") })));
        }
        if (request.method === "PUT") {
          const b = await request.json();
          if (!reMes.test(b.periodo || "")) return json({ error: "Período inválido" }, 400);
          if (await periodoCerrado(b.periodo)) return json({ error: "El período " + b.periodo + " está cerrado" }, 409);
          const filas = Array.isArray(b.filas) ? b.filas : [];
          let n = 0;
          for (const f of filas) {
            const legajo = Number(f.legajo);
            if (!Number.isInteger(legajo) || !Array.isArray(f.codigos) || f.codigos.length < 28 || f.codigos.length > 31) continue;
            const codigos = f.codigos.map((c) => String(c || "").toUpperCase().replace(/[|\n]/g, "").slice(0, 12)).join("|");
            const lab = Number.isFinite(Number(f.laborables)) ? Math.round(Number(f.laborables)) : null;
            await sql`
              INSERT INTO rrhh_aus_mes (periodo, legajo, codigos, laborables, fuente, actualizado_por, actualizado_en)
              VALUES (${b.periodo}, ${legajo}, ${codigos}, ${lab}, ${String(b.fuente || "").slice(0, 120) || null}, ${usuarioToken}, now())
              ON CONFLICT (periodo, legajo) DO UPDATE SET codigos = EXCLUDED.codigos, laborables = EXCLUDED.laborables,
                fuente = EXCLUDED.fuente, actualizado_por = EXCLUDED.actualizado_por, actualizado_en = now()`;
            n++;
          }
          return json({ ok: true, guardados: n });
        }
      }

      // GET /api/apc/capacitacion-resumen?anio=2026 -> {programadas, cumplidas, valor} para el Apéndice C (sin nombres)
      if (request.method === "GET" && parts[1] === "apc" && parts[2] === "capacitacion-resumen") {
        const anio = Number(url.searchParams.get("anio")) || new Date().getUTCFullYear();
        const [r] = await sql`
          SELECT count(*) FILTER (WHERE programada AND estado <> 'Cancelada')::int AS programadas,
                 count(*) FILTER (WHERE programada AND estado = 'Cumplida')::int AS cumplidas
          FROM rrhh_capacitaciones WHERE anio = ${anio}`;
        return json({ anio, programadas: r.programadas, cumplidas: r.cumplidas, valor: r.programadas ? r.cumplidas / r.programadas : null, cerrado: await anioCerrado(anio) });
      }

      return json({ error: "Ruta no encontrada" }, 404);
    } catch (err) {
      return json({ error: err.message }, 500);
    }
  },
};
