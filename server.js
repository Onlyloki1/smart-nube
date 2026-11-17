// Smart Nube — backend de Smart Acquisition: login, usuarios (con admin para echar gente) y relay de sesiones.
// Todo en memoria + archivo (MVP). Para producción se puede mover a Postgres sin cambiar la API.
import http from "node:http";
import fs from "node:fs";
import crypto from "node:crypto";

const PORT = process.env.PORT || 3000;
const FILE = process.env.DATA_FILE || "./nube.json";
const SECRET = process.env.SECRET || "cambia-esto-en-railway-9f3k2";
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "juan@gmail.com").toLowerCase();
const ADMIN_PASS = process.env.ADMIN_PASS || "cambiar123";
const VENCE_MS = 2 * 60 * 60 * 1000; // sesión del setter sin bajar se borra a las 2 h

// ---------- almacén ----------
function leer() { try { return JSON.parse(fs.readFileSync(FILE, "utf8")); } catch { return { usuarios: {}, colas: {} }; } }
function guardar(o) { try { fs.writeFileSync(FILE, JSON.stringify(o)); } catch {} }
function hashPass(pass, salt) { return crypto.scryptSync(pass, salt, 32).toString("hex"); }
function nuevoUsuario(o, email, pass, rol) {
  const salt = crypto.randomBytes(8).toString("hex");
  o.usuarios[email] = { hash: hashPass(pass, salt), salt, activo: true, rol: rol || "user", creado: Date.now() };
}
function token(email) { return crypto.createHmac("sha256", SECRET).update(email).digest("base64url"); }

// crear el admin la primera vez
(function initAdmin() {
  const o = leer();
  if (!o.usuarios[ADMIN_EMAIL]) { nuevoUsuario(o, ADMIN_EMAIL, ADMIN_PASS, "admin"); guardar(o); }
})();

// ---------- http helpers ----------
const cuerpo = req => new Promise((ok, no) => { let b = ""; req.on("data", c => { b += c; if (b.length > 5e6) req.destroy(); }); req.on("end", () => { try { ok(b ? JSON.parse(b) : {}); } catch (e) { no(e); } }); });
const json = (r, c, d) => { r.writeHead(c, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "Content-Type", "Access-Control-Allow-Methods": "GET,POST,OPTIONS" }); r.end(JSON.stringify(d)); };
const limpiar = arr => (arr || []).filter(x => Date.now() - x.ts < VENCE_MS);
// valida email+token y que esté activo; devuelve el usuario o null
function auth(o, email, tok) { const e = String(email || "").toLowerCase(); const u = o.usuarios[e]; if (!u || !u.activo) return null; if (tok !== token(e)) return null; return { email: e, ...u }; }

http.createServer(async (req, res) => {
  const u = new URL(req.url, "http://x");
  const p = u.pathname;
  if (req.method === "OPTIONS") { res.writeHead(204, { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "Content-Type", "Access-Control-Allow-Methods": "GET,POST,OPTIONS" }); return res.end(); }
  try {
    const o = leer();

    // ---- LOGIN del software ----
    if (req.method === "POST" && p === "/login") {
      const { email, pass } = await cuerpo(req);
      const e = String(email || "").trim().toLowerCase();
      const us = o.usuarios[e];
      if (!us) return json(res, 403, { error: "No existe esa cuenta." });
      if (!us.activo) return json(res, 403, { error: "Tu cuenta está deshabilitada. Hablá con el admin." });
      if (hashPass(String(pass || ""), us.salt) !== us.hash) return json(res, 403, { error: "Contraseña incorrecta." });
      return json(res, 200, { ok: true, email: e, rol: us.rol, token: token(e) });
    }
    // ---- ¿sigo habilitado? (el software lo chequea seguido; si lo echaron, se bloquea) ----
    if (req.method === "GET" && p === "/me") {
      const us = auth(o, u.searchParams.get("email"), u.searchParams.get("token"));
      if (!us) return json(res, 403, { error: "sesión inválida o deshabilitada" });
      return json(res, 200, { ok: true, email: us.email, rol: us.rol });
    }

    // ---- ADMIN: gestionar usuarios (echar, crear, prender) ----
    if (p.startsWith("/admin/")) {
      const b = req.method === "POST" ? await cuerpo(req) : {};
      const quien = auth(o, b.email || u.searchParams.get("email"), b.token || u.searchParams.get("token"));
      if (!quien || quien.rol !== "admin") return json(res, 403, { error: "solo admin" });
      if (req.method === "GET" && p === "/admin/usuarios") {
        return json(res, 200, { usuarios: Object.entries(o.usuarios).map(([em, x]) => ({ email: em, activo: x.activo, rol: x.rol, creado: x.creado })) });
      }
      if (req.method === "POST" && p === "/admin/crear") {
        const e = String(b.nuevoEmail || "").trim().toLowerCase();
        if (!e || !b.nuevaPass) return json(res, 400, { error: "falta email o contraseña" });
        if (o.usuarios[e]) return json(res, 409, { error: "ya existe" });
        nuevoUsuario(o, e, String(b.nuevaPass), b.rol === "admin" ? "admin" : "user"); guardar(o);
        return json(res, 200, { ok: true });
      }
      if (req.method === "POST" && p === "/admin/estado") {
        const e = String(b.objetivo || "").trim().toLowerCase();
        if (!o.usuarios[e]) return json(res, 404, { error: "no existe" });
        if (e === ADMIN_EMAIL) return json(res, 400, { error: "no podés deshabilitar al admin principal" });
        o.usuarios[e].activo = !!b.activo; guardar(o);
        return json(res, 200, { ok: true, activo: o.usuarios[e].activo });
      }
      return json(res, 404, { error: "no existe" });
    }

    // ---- RELAY: la extensión del setter sube la sesión (solo el mail del dueño) ----
    if (req.method === "POST" && p === "/subir") {
      const { email, sesion, usuario, userId } = await cuerpo(req);
      const e = String(email || "").trim().toLowerCase();
      if (!e || !sesion) return json(res, 400, { error: "faltan email o sesión" });
      if (!o.usuarios[e] || !o.usuarios[e].activo) return json(res, 403, { error: "ese dueño no existe o está deshabilitado" });
      o.colas[e] = limpiar(o.colas[e]); o.colas[e].push({ sesion, usuario: usuario || "", userId: userId || "", ts: Date.now() });
      guardar(o);
      return json(res, 200, { ok: true });
    }
    // ---- RELAY: el software del dueño baja las sesiones nuevas (mail + token) ----
    if (req.method === "GET" && p === "/bajar") {
      const us = auth(o, u.searchParams.get("email"), u.searchParams.get("token"));
      if (!us) return json(res, 403, { error: "sesión inválida" });
      const items = limpiar(o.colas[us.email]); o.colas[us.email] = []; guardar(o);
      return json(res, 200, { sesiones: items });
    }

    if (p === "/") return json(res, 200, { ok: true, servicio: "smart-nube" });
    json(res, 404, { error: "no existe" });
  } catch (e) { json(res, 500, { error: e.message }); }
}).listen(PORT, () => console.log("Smart Nube en puerto " + PORT));
