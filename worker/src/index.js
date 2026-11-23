/**
 * PDF 線上編輯器 — 後端（Cloudflare Workers）
 *
 *  - Google 登入驗證（Firebase ID token，用 Google 公開金鑰驗簽）
 *  - 試用次數 / 付費方案判斷（一定要在後端判斷，前端無法竄改）
 *  - 批次線上簽名：上傳報名表、產生每位學生專屬簽名網址（網頁上匯出名單，不寄信）、簽名回傳後鎖定、退回重簽
 *  - 綠界 ECPay 付款建立與付款結果通知（驗證 CheckMacValue）
 *  - 每日排程：刪除過期批次
 *  - 網頁（web 資料夾）也由這個 Worker 一起提供，網頁和後端同一個網址
 *
 * 綁定：DB (D1)、FILES (R2)、ASSETS（網頁）。設定值見 wrangler.toml 的 [vars] 與 README。
 * 資料表會在第一次有人連線時自動建立，不用另外執行 schema.sql。
 */

/* ============================== 基本工具 ============================== */
class HttpError extends Error { constructor(status, message, extra) { super(message); this.status = status; this.extra = extra || {}; } }
const now = () => Date.now();
const DAY = 86400000;
const enc = new TextEncoder();

function corsHeaders(req, env) {
  const origin = req.headers.get('Origin');
  const allow = (env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
  const h = { 'Vary': 'Origin' };
  if (origin && (allow.includes(origin) || allow.includes('*'))) {
    h['Access-Control-Allow-Origin'] = origin;
    h['Access-Control-Allow-Headers'] = 'Authorization, Content-Type, X-File-Name, X-Meta';
    h['Access-Control-Allow-Methods'] = 'GET, POST, PATCH, DELETE, OPTIONS';
    h['Access-Control-Max-Age'] = '86400';
  }
  return h;
}
function json(data, status, req, env) {
  return new Response(JSON.stringify(data), { status: status || 200, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...corsHeaders(req, env) } });
}
async function body(req) { try { return await req.json(); } catch (e) { throw new HttpError(400, '資料格式錯誤'); } }
function b64url(bytes) { let s = ''; for (const b of bytes) s += String.fromCharCode(b); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function b64urlDecode(s) { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; const bin = atob(s); const out = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i); return out; }
const randId = (n = 12) => b64url(crypto.getRandomValues(new Uint8Array(n)));
async function sha256hex(str) { const d = await crypto.subtle.digest('SHA-256', enc.encode(str)); return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, '0')).join(''); }
const intVar = (env, k, d) => { const v = parseInt(env[k], 10); return Number.isFinite(v) ? v : d; };
const jsonVar = (env, k, d) => { try { return env[k] ? (typeof env[k] === 'string' ? JSON.parse(env[k]) : env[k]) : d; } catch (e) { return d; } };
const twNow = () => new Date(now() + 8 * 3600000);              // 台灣時間（UTC+8）
const twDayStart = () => { const d = twNow(); return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()) - 8 * 3600000; };
const twMonthStart = () => { const d = twNow(); return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1) - 8 * 3600000; };
const escHtml = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const normEmail = e => String(e || '').trim().toLowerCase();
const maskEmail = e => { const [u, d] = String(e || '').split('@'); if (!d) return ''; return (u.length <= 2 ? u[0] + '*' : u.slice(0, 2) + '***') + '@' + d; };

/* ============================== Firebase 登入驗證 ============================== */
let JWKS = null, JWKS_EXP = 0;
async function googleKeys() {
  if (JWKS && JWKS_EXP > now()) return JWKS;
  const r = await fetch('https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com', { cf: { cacheTtl: 3600 } });
  if (!r.ok) throw new HttpError(503, '暫時無法驗證登入，請稍後再試');
  const m = /max-age=(\d+)/.exec(r.headers.get('Cache-Control') || '');
  JWKS = (await r.json()).keys; JWKS_EXP = now() + (m ? +m[1] * 1000 : 3600000);
  return JWKS;
}
async function verifyIdToken(token, env) {
  if (env.DEV_AUTH === 'on' && token.startsWith('dev:')) {      // 只給本機測試用，正式環境絕對不要打開
    const email = normEmail(token.slice(4)); return { uid: 'dev-' + email, email, name: email.split('@')[0], email_verified: true };
  }
  const parts = token.split('.'); if (parts.length !== 3) throw new HttpError(401, '登入資訊無效，請重新登入');
  let header, payload;
  try { header = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[0]))); payload = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[1]))); }
  catch (e) { throw new HttpError(401, '登入資訊無效，請重新登入'); }
  if (header.alg !== 'RS256') throw new HttpError(401, '登入資訊無效，請重新登入');
  let jwk = (await googleKeys()).find(k => k.kid === header.kid);
  if (!jwk) { JWKS_EXP = 0; jwk = (await googleKeys()).find(k => k.kid === header.kid); }
  if (!jwk) throw new HttpError(401, '登入已過期，請重新登入');
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64urlDecode(parts[2]), enc.encode(parts[0] + '.' + parts[1]));
  if (!ok) throw new HttpError(401, '登入資訊無效，請重新登入');
  const pid = env.FIREBASE_PROJECT_ID; const t = Math.floor(now() / 1000);
  if (payload.aud !== pid || payload.iss !== 'https://securetoken.google.com/' + pid) throw new HttpError(401, '登入資訊不屬於本網站');
  if (!(payload.exp > t - 30) || !(payload.iat < t + 300) || !payload.sub) throw new HttpError(401, '登入已過期，請重新登入');
  return { uid: payload.sub, email: normEmail(payload.email), name: payload.name || '', email_verified: !!payload.email_verified };
}
async function authUser(req, env, required = true) {
  const h = req.headers.get('Authorization') || '';
  const token = h.startsWith('Bearer ') ? h.slice(7).trim() : '';
  if (!token) { if (required) throw new HttpError(401, '請先用 Google 帳號登入', { need_login: true }); return null; }
  const u = await verifyIdToken(token, env);
  await env.DB.prepare('INSERT INTO users (uid, email, name, created_at, last_seen) VALUES (?1, ?2, ?3, ?4, ?4) ON CONFLICT(uid) DO NOTHING')
    .bind(u.uid, u.email, u.name, now()).run();
  return u;
}
const isSiteAdmin = (u, env) => !!u && (env.SITE_ADMINS || '').split(',').map(normEmail).includes(u.email);

/* ============================== 方案、簽名份數與試用 ==============================
 * 兩種商品：
 *  1. 進階版（pro_days）：編輯器的掃描文字辨識、Office 轉檔不限次數。免費版每月各有 FREE_QUOTA 次。
 *  2. 批次簽名份數（credits）：每上傳一份要簽名的文件扣 1 份，買了 credit_days 天內用完。
 *     免費試用 FREE_DOC_CREDITS 份（每個帳號一次），試用批次最多保存 FREE_RETAIN_DAYS 天。
 *  還沒寄出就刪掉的文件會把份數還回去。
 */
const DEFAULT_PLANS = {
  pro_m: { name: '進階版 1 個月', price: 99, pro_days: 31, pay: 'Credit' },
  pro_y: { name: '進階版 1 年', price: 790, pro_days: 366 },
  sign300: { name: '批次簽名 300 份', price: 390, credits: 300, credit_days: 365 },
  sign1000: { name: '批次簽名 1,000 份＋進階版 1 年', price: 990, credits: 1000, credit_days: 365, pro_days: 366 },
  sign3000: { name: '批次簽名 3,000 份＋進階版 1 年', price: 2490, credits: 3000, credit_days: 365, pro_days: 366 }
};
function plans(env) { return jsonVar(env, 'PLANS', DEFAULT_PLANS); }
function freeQuota(env) { return jsonVar(env, 'FREE_QUOTA', { ocr: 10, convert: 10 }); }   // 每個月重新計算
async function account(u, env) {
  const row = (await env.DB.prepare('SELECT * FROM users WHERE uid = ?').bind(u.uid).first()) || {};
  const paidUntil = row.paid_until || 0; const pro = paidUntil > now();
  const creditsLive = (row.credits_until || 0) > now();
  const trialLimit = intVar(env, 'FREE_DOC_CREDITS', 30);
  const used = {}; const q = freeQuota(env);
  const { results } = await env.DB.prepare('SELECT feature, COUNT(*) AS n FROM usage WHERE uid = ? AND trial = 1 AND created_at >= ? GROUP BY feature').bind(u.uid, twMonthStart()).all();
  for (const r of results) used[r.feature] = r.n;
  const quota = {}; for (const f of Object.keys(q)) quota[f] = { limit: q[f], used: used[f] || 0, remaining: Math.max(0, q[f] - (used[f] || 0)), monthly: true };
  return {
    uid: u.uid, email: u.email, name: u.name, paid: pro, paid_until: paidUntil || null, quota,
    credits: { paid: creditsLive ? (row.doc_credits || 0) : 0, paid_until: creditsLive ? row.credits_until : null, expired: !creditsLive && (row.doc_credits || 0) > 0 ? row.doc_credits : 0,
      trial: Math.max(0, trialLimit - (row.trial_docs || 0)), trial_limit: trialLimit },
    site_admin: isSiteAdmin(u, env)
  };
}
async function consume(u, env, feature) {
  const q = freeQuota(env); if (!(feature in q)) throw new HttpError(400, '未知的功能');
  const acc = await account(u, env);
  if (acc.paid) { await env.DB.prepare('INSERT INTO usage (uid, feature, trial, created_at) VALUES (?, ?, 0, ?)').bind(u.uid, feature, now()).run(); return { ok: true, paid: true }; }
  const left = acc.quota[feature].remaining;
  if (left <= 0) throw new HttpError(402, `這個月的免費次數（${q[feature]} 次）已經用完，下個月 1 日會重新計算；開通進階版就不限次數`, { need_pay: true, feature });
  await env.DB.prepare('INSERT INTO usage (uid, feature, trial, created_at) VALUES (?, ?, 1, ?)').bind(u.uid, feature, now()).run();
  return { ok: true, paid: false, remaining: left - 1 };
}
/* 扣 1 份：試用批次先用試用份數，用完而且有買份數時，批次自動轉成付費批次 */
async function spendCredit(env, u, b) {
  if (b.trial) {
    const r = await env.DB.prepare('UPDATE users SET trial_docs = COALESCE(trial_docs, 0) + 1 WHERE uid = ? AND COALESCE(trial_docs, 0) < ?').bind(u.uid, intVar(env, 'FREE_DOC_CREDITS', 30)).run();
    if (r.meta.changes) return 'trial';
  }
  const r = await env.DB.prepare('UPDATE users SET doc_credits = doc_credits - 1 WHERE uid = ? AND doc_credits > 0 AND credits_until > ?').bind(u.uid, now()).run();
  if (r.meta.changes) {
    if (b.trial) { await env.DB.prepare('UPDATE batches SET trial = 0 WHERE id = ?').bind(b.id).run(); b.trial = 0; }
    return 'paid';
  }
  throw new HttpError(402, b.trial ? `免費試用的 ${intVar(env, 'FREE_DOC_CREDITS', 30)} 份已經用完，購買簽名份數就能繼續上傳` : '簽名份數已經用完（或已過期），請購買份數後再上傳', { need_pay: true });
}
async function refundCredit(env, uid, kind) {
  if (kind === 'trial') await env.DB.prepare('UPDATE users SET trial_docs = MAX(0, COALESCE(trial_docs, 0) - 1) WHERE uid = ?').bind(uid).run();
  else if (kind === 'paid') await env.DB.prepare('UPDATE users SET doc_credits = COALESCE(doc_credits, 0) + 1 WHERE uid = ?').bind(uid).run();
}
const refundable = d => d.status === 'pending' && !d.sent_count && !d.sent_at;
/* 付款成功或管理者手動開通：加進階版天數、加份數（新份數的期限會把舊份數一起延長） */
function grantStmts(env, uid, { pro_days, credits, credit_days }, reason, ref) {
  const t = now(); const s = [];
  if (pro_days) s.push(env.DB.prepare('UPDATE users SET paid_until = MAX(COALESCE(paid_until, 0), ?1) + ?2 WHERE uid = ?3').bind(t, pro_days * DAY, uid));
  if (credits) {
    s.push(env.DB.prepare('UPDATE users SET doc_credits = (CASE WHEN COALESCE(credits_until, 0) > ?1 THEN COALESCE(doc_credits, 0) ELSE 0 END) + ?2, credits_until = MAX(COALESCE(credits_until, 0), ?3) WHERE uid = ?4')
      .bind(t, credits, t + (credit_days || 365) * DAY, uid));
  }
  s.push(env.DB.prepare('INSERT INTO credit_log (uid, credits, pro_days, reason, ref, created_at) VALUES (?,?,?,?,?,?)').bind(uid, credits || 0, pro_days || 0, reason, ref || '', t));
  return s;
}
async function storedBytes(env) { const r = await env.DB.prepare('SELECT COALESCE(SUM(orig_size),0) + COALESCE(SUM(signed_size),0) AS bytes FROM docs').first(); return r.bytes || 0; }

/* ============================== 簽名網址 ============================== */
// SITE_URL 沒填時，用目前網站的網址（Worker 同時提供網頁和後端，所以一定對）
const siteBase = (env, req) => (env.SITE_URL || (req ? new URL(req.url).origin : '')).replace(/\/$/, '');
function signUrl(env, token, req) { return `${siteBase(env, req)}/sign.html?t=${token}`; }

/* ============================== 批次簽名 ============================== */
async function ownBatch(env, u, id) {
  const b = await env.DB.prepare('SELECT * FROM batches WHERE id = ?').bind(id).first();
  if (!b || b.owner_uid !== u.uid) throw new HttpError(404, '找不到這個批次');
  return b;
}
async function ownDoc(env, u, id) {
  const d = await env.DB.prepare('SELECT * FROM docs WHERE id = ?').bind(id).first();
  if (!d || d.owner_uid !== u.uid) throw new HttpError(404, '找不到這份文件');
  return d;
}
const docOut = (env, d, req) => ({ id: d.id, filename: d.filename, student_id: d.student_id, student_name: d.student_name, email: d.email, status: d.status,
  sign_url: signUrl(env, d.token, req), sent_at: d.sent_at, sent_count: d.sent_count, signed_at: d.signed_at, signed_email: d.signed_email, return_reason: d.return_reason, orig_size: d.orig_size, signed_size: d.signed_size });
async function readPdf(req, env) {
  const max = intVar(env, 'MAX_PDF_MB', 20) * 1048576;
  const len = +req.headers.get('Content-Length') || 0; if (len > max) throw new HttpError(413, `檔案太大，上限 ${env.MAX_PDF_MB || 20} MB`);
  const buf = await req.arrayBuffer(); if (buf.byteLength > max) throw new HttpError(413, `檔案太大，上限 ${env.MAX_PDF_MB || 20} MB`);
  const head = new Uint8Array(buf.slice(0, 1024)); const s = String.fromCharCode(...head);
  if (!s.includes('%PDF-')) throw new HttpError(415, '這不是 PDF 檔');
  return buf;
}
async function deleteKeys(env, keys) { keys = keys.filter(Boolean); for (let i = 0; i < keys.length; i += 900) await env.FILES.delete(keys.slice(i, i + 900)); }
async function deleteBatch(env, b) {
  const { results } = await env.DB.prepare('SELECT orig_key, signed_key FROM docs WHERE batch_id = ?').bind(b.id).all();
  await deleteKeys(env, results.flatMap(r => [r.orig_key, r.signed_key]));
  await env.DB.batch([env.DB.prepare('DELETE FROM docs WHERE batch_id = ?').bind(b.id), env.DB.prepare('DELETE FROM batches WHERE id = ?').bind(b.id)]);
}
function fileResponse(obj, name, req, env, inline = true) {
  const h = new Headers(corsHeaders(req, env));
  h.set('Content-Type', 'application/pdf'); h.set('Cache-Control', 'private, no-store');
  h.set('Content-Disposition', `${inline ? 'inline' : 'attachment'}; filename*=UTF-8''${encodeURIComponent(name)}`);
  h.set('X-Content-Type-Options', 'nosniff');
  return new Response(obj.body, { headers: h });
}
/* 學生端：用簽名網址裡的 token 找文件，必要時要求本人 Google 登入 */
async function signDoc(req, env, token) {
  if (!/^[A-Za-z0-9_-]{20,64}$/.test(token)) throw new HttpError(404, '簽名網址不正確');
  const d = await env.DB.prepare('SELECT d.*, b.name AS batch_name, b.org_name, b.message, b.deadline, b.require_login, b.retain_until FROM docs d JOIN batches b ON b.id = d.batch_id WHERE d.token = ?').bind(token).first();
  if (!d) throw new HttpError(404, '找不到這份文件，可能已被刪除或網址不完整');
  if (d.require_login) {
    const u = await authUser(req, env, false);
    if (!u) throw new HttpError(401, '請用學校通知你的 Google 帳號登入', { need_login: true, hint: maskEmail(d.email) });
    if (u.email !== normEmail(d.email) || !u.email_verified) throw new HttpError(403, `這份文件只開放給 ${maskEmail(d.email)} 開啟，請改用那個帳號登入`, { wrong_account: true, hint: maskEmail(d.email) });
    d._viewer = u.email;
  }
  return d;
}

/* ============================== 綠界 ECPay ============================== */
function ecpayEncode(s) {   // 綠界規定的 .NET 版 URL encode
  return encodeURIComponent(s).replace(/%20/g, '+').replace(/~/g, '%7e').replace(/'/g, '%27');
}
async function ecpayMac(params, env) {
  const keys = Object.keys(params).filter(k => k !== 'CheckMacValue').sort((a, b) => { const x = a.toLowerCase(), y = b.toLowerCase(); return x < y ? -1 : x > y ? 1 : 0; });
  const raw = `HashKey=${env.ECPAY_HASH_KEY}&` + keys.map(k => `${k}=${params[k]}`).join('&') + `&HashIV=${env.ECPAY_HASH_IV}`;
  return (await sha256hex(ecpayEncode(raw).toLowerCase())).toUpperCase();
}
function ecpayDate() { const d = twNow().toISOString(); return d.slice(0, 10).replace(/-/g, '/') + ' ' + d.slice(11, 19); }
function timingSafeEq(a, b) { if (a.length !== b.length) return false; let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0; }

/* ============================== 路由 ============================== */
async function route(req, env, ctx) {
  const url = new URL(req.url); const p = url.pathname.replace(/\/+$/, ''); const M = req.method;
  if (M === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders(req, env) });
  const J = (d, s) => json(d, s, req, env);
  let m;

  if (p === '/api/health') return J({ ok: true, time: now() });
  if (p === '/api/config' && M === 'GET') return J({ plans: plans(env), free_quota: freeQuota(env), free_doc_credits: intVar(env, 'FREE_DOC_CREDITS', 30), free_retain_days: intVar(env, 'FREE_RETAIN_DAYS', 14),
    free_max_batches: intVar(env, 'FREE_MAX_BATCHES', 2), max_retain_days: intVar(env, 'MAX_RETAIN_DAYS', 180), max_pdf_mb: intVar(env, 'MAX_PDF_MB', 10), site_name: env.SITE_NAME || '', support_email: env.SUPPORT_EMAIL || '' });

  /* ---------- 帳號 ---------- */
  if (p === '/api/me' && M === 'GET') {
    const u = await authUser(req, env);
    await env.DB.prepare('UPDATE users SET email = ?, name = ?, last_seen = ? WHERE uid = ?').bind(u.email, u.name, now(), u.uid).run();
    return J(await account(u, env));
  }
  if (p === '/api/usage/consume' && M === 'POST') { const u = await authUser(req, env); const { feature } = await body(req); return J(await consume(u, env, feature)); }

  /* ---------- 學生簽名（公開網址＋token） ---------- */
  if ((m = p.match(/^\/api\/sign\/([^/]+)$/)) && M === 'GET') {
    const d = await signDoc(req, env, m[1]);
    return J({ filename: d.filename, status: d.status, signed_at: d.signed_at, return_reason: d.status === 'returned' ? d.return_reason : null,
      student_name: d.student_name, batch: { name: d.batch_name, org: d.org_name, message: d.message, deadline: d.deadline }, expired: !!(d.deadline && now() > d.deadline + DAY) });
  }
  if ((m = p.match(/^\/api\/sign\/([^/]+)\/file$/)) && M === 'GET') {
    const d = await signDoc(req, env, m[1]);
    const key = d.status === 'signed' ? d.signed_key : d.orig_key;
    const obj = await env.FILES.get(key); if (!obj) throw new HttpError(404, '檔案不存在');
    return fileResponse(obj, d.status === 'signed' ? signedName(d.filename) : d.filename, req, env);
  }
  if ((m = p.match(/^\/api\/sign\/([^/]+)\/submit$/)) && M === 'POST') {
    const d = await signDoc(req, env, m[1]);
    if (d.status === 'signed') throw new HttpError(409, '這份文件已經簽好了，不能再修改');
    if (d.deadline && now() > d.deadline + DAY) throw new HttpError(403, '已經超過簽名期限，請聯絡承辦人員');
    const buf = await readPdf(req, env);
    const key = `b/${d.batch_id}/${d.id}/signed-${randId(6)}.pdf`;
    await env.FILES.put(key, buf, { httpMetadata: { contentType: 'application/pdf' } });
    const ip = req.headers.get('CF-Connecting-IP') || '';
    const r = await env.DB.prepare("UPDATE docs SET status = 'signed', signed_key = ?, signed_size = ?, signed_at = ?, signed_ip = ?, signed_email = ? WHERE id = ? AND status != 'signed'")
      .bind(key, buf.byteLength, now(), ip, d._viewer || '', d.id).run();
    if (!r.meta.changes) { await env.FILES.delete(key); throw new HttpError(409, '這份文件已經簽好了，不能再修改'); }
    return J({ ok: true, signed_at: now() });
  }

  /* ---------- 批次管理（需登入） ---------- */
  if (p === '/api/batches' && M === 'GET') {
    const u = await authUser(req, env);
    const { results } = await env.DB.prepare(`SELECT b.*, COUNT(d.id) AS total, SUM(CASE WHEN d.status='signed' THEN 1 ELSE 0 END) AS signed,
      SUM(CASE WHEN d.sent_at IS NOT NULL THEN 1 ELSE 0 END) AS sent FROM batches b LEFT JOIN docs d ON d.batch_id = b.id WHERE b.owner_uid = ? GROUP BY b.id ORDER BY b.created_at DESC`).bind(u.uid).all();
    return J({ batches: results });
  }
  if (p === '/api/batches' && M === 'POST') {
    const u = await authUser(req, env); const x = await body(req);
    const name = String(x.name || '').trim().slice(0, 100); if (!name) throw new HttpError(400, '請輸入批次名稱');
    const acc = await account(u, env); const paid = acc.credits.paid > 0;
    if (!paid) {
      if (acc.credits.trial <= 0) throw new HttpError(402, `免費試用的 ${acc.credits.trial_limit} 份已經用完，購買簽名份數就能建立新的批次`, { need_pay: true });
      const open = await env.DB.prepare('SELECT COUNT(*) AS n FROM batches WHERE owner_uid = ? AND trial = 1').bind(u.uid).first();
      if (open.n >= intVar(env, 'FREE_MAX_BATCHES', 2)) throw new HttpError(402, `免費試用最多同時有 ${intVar(env, 'FREE_MAX_BATCHES', 2)} 個批次，請先刪除舊的試用批次，或購買簽名份數`, { need_pay: true });
    }
    const maxKeep = paid ? intVar(env, 'MAX_RETAIN_DAYS', 180) : intVar(env, 'FREE_RETAIN_DAYS', 14);
    const retain = Math.max(now() + DAY, Math.min(now() + maxKeep * DAY, +x.retain_until || now() + (paid ? 90 : maxKeep) * DAY));
    const id = randId(9);
    await env.DB.prepare('INSERT INTO batches (id, owner_uid, name, org_name, message, deadline, require_login, retain_until, created_at, trial) VALUES (?,?,?,?,?,?,?,?,?,?)')
      .bind(id, u.uid, name, String(x.org_name || '').slice(0, 100), String(x.message || '').slice(0, 2000), +x.deadline || null, x.require_login === false ? 0 : 1, retain, now(), paid ? 0 : 1).run();
    return J({ id, retain_until: retain, trial: !paid });
  }
  if ((m = p.match(/^\/api\/batches\/([^/]+)$/))) {
    const u = await authUser(req, env); const b = await ownBatch(env, u, m[1]);
    if (M === 'GET') {
      const { results } = await env.DB.prepare('SELECT * FROM docs WHERE batch_id = ? ORDER BY filename').bind(b.id).all();
      const acc = await account(u, env);
      const room = Math.min(intVar(env, 'MAX_BATCH_DOCS', 3000) - results.length, (b.trial ? acc.credits.trial : 0) + acc.credits.paid);
      return J({ batch: b, docs: results.map(d => docOut(env, d, req)), doc_limit: results.length + Math.max(0, room), credits: acc.credits });
    }
    if (M === 'PATCH') {
      const x = await body(req);
      await env.DB.prepare('UPDATE batches SET name = COALESCE(?, name), org_name = COALESCE(?, org_name), message = COALESCE(?, message), deadline = COALESCE(?, deadline), require_login = COALESCE(?, require_login) WHERE id = ?')
        .bind(x.name ?? null, x.org_name ?? null, x.message ?? null, x.deadline ?? null, x.require_login == null ? null : (x.require_login ? 1 : 0), b.id).run();
      return J({ ok: true });
    }
    if (M === 'DELETE') {
      const { results } = await env.DB.prepare('SELECT * FROM docs WHERE batch_id = ?').bind(b.id).all();
      let back = 0; for (const d of results) if (refundable(d) && d.credit) { await refundCredit(env, u.uid, d.credit); back++; }
      await deleteBatch(env, b); return J({ ok: true, refunded: back });
    }
  }
  if ((m = p.match(/^\/api\/batches\/([^/]+)\/docs$/)) && M === 'POST') {
    const u = await authUser(req, env); const b = await ownBatch(env, u, m[1]);
    const max = intVar(env, 'MAX_BATCH_DOCS', 3000);
    const c = await env.DB.prepare('SELECT COUNT(*) AS n FROM docs WHERE batch_id = ?').bind(b.id).first();
    if (c.n >= max) throw new HttpError(413, `一個批次最多 ${max} 份文件，請另外建立一個批次`);
    const buf = await readPdf(req, env);
    if (b.trial) {   // 免費試用的總空間到警戒線時，先停止試用上傳；付費的照常（超過的空間每 GB 每月只要幾毛美金）
      const guard = intVar(env, 'TRIAL_STORAGE_GUARD_GB', 8) * 1073741824;
      if (guard > 0 && (await storedBytes(env)) + buf.byteLength > guard) throw new HttpError(503, '網站的免費試用空間暫時額滿，請過幾天再試，或購買簽名份數後馬上就能上傳', { need_pay: true, storage_full: true });
    }
    let meta = {}; try { meta = JSON.parse(decodeURIComponent(req.headers.get('X-Meta') || '%7B%7D')); } catch (e) { }
    const filename = String(meta.filename || 'document.pdf').slice(0, 200);
    const credit = await spendCredit(env, u, b);
    const id = randId(9), token = randId(24), key = `b/${b.id}/${id}/orig.pdf`;
    try {
      await env.FILES.put(key, buf, { httpMetadata: { contentType: 'application/pdf' } });
      await env.DB.prepare("INSERT INTO docs (id, batch_id, owner_uid, filename, student_id, student_name, email, token, status, orig_key, orig_size, sent_count, created_at, credit) VALUES (?,?,?,?,?,?,?,?, 'pending', ?, ?, 0, ?, ?)")
        .bind(id, b.id, u.uid, filename, String(meta.student_id || '').slice(0, 40), String(meta.student_name || '').slice(0, 60), normEmail(meta.email).slice(0, 200), token, key, buf.byteLength, now(), credit).run();
    } catch (e) { await refundCredit(env, u.uid, credit); try { await env.FILES.delete(key); } catch (e2) { } throw e; }
    const d = await env.DB.prepare('SELECT * FROM docs WHERE id = ?').bind(id).first();
    return J({ doc: docOut(env, d, req) });
  }
  if ((m = p.match(/^\/api\/batches\/([^/]+)\/mark-sent$/)) && M === 'POST') {    // 匯出／複製名單後標記為「已發出」（之後刪除就不退份數）
    const u = await authUser(req, env); const b = await ownBatch(env, u, m[1]); const x = await body(req);
    const ids = (Array.isArray(x.ids) ? x.ids : []).slice(0, 3000); const t = now();
    for (let i = 0; i < ids.length; i += 50) await env.DB.batch(ids.slice(i, i + 50).map(id => env.DB.prepare("UPDATE docs SET sent_at = COALESCE(sent_at, ?), sent_count = MAX(sent_count, 1), status = CASE WHEN status = 'pending' THEN 'sent' ELSE status END WHERE id = ? AND batch_id = ?").bind(t, id, b.id)));
    return J({ ok: true, marked: ids.length });
  }
  if ((m = p.match(/^\/api\/docs\/([^/]+)$/))) {
    const u = await authUser(req, env); const d = await ownDoc(env, u, m[1]);
    if (M === 'PATCH') {
      const x = await body(req);
      await env.DB.prepare('UPDATE docs SET email = COALESCE(?, email), student_name = COALESCE(?, student_name), student_id = COALESCE(?, student_id) WHERE id = ?')
        .bind(x.email == null ? null : normEmail(x.email), x.student_name ?? null, x.student_id ?? null, d.id).run();
      return J({ doc: docOut(env, await env.DB.prepare('SELECT * FROM docs WHERE id = ?').bind(d.id).first(), req) });
    }
    if (M === 'DELETE') {
      await deleteKeys(env, [d.orig_key, d.signed_key]); await env.DB.prepare('DELETE FROM docs WHERE id = ?').bind(d.id).run();
      const back = refundable(d) && d.credit ? (await refundCredit(env, u.uid, d.credit), true) : false;
      return J({ ok: true, refunded: back });
    }
  }
  if ((m = p.match(/^\/api\/docs\/([^/]+)\/file$/)) && M === 'GET') {
    const u = await authUser(req, env); const d = await ownDoc(env, u, m[1]);
    const signed = url.searchParams.get('v') === 'signed'; const key = signed ? d.signed_key : d.orig_key;
    if (!key) throw new HttpError(404, '這份文件還沒有簽名檔');
    const obj = await env.FILES.get(key); if (!obj) throw new HttpError(404, '檔案不存在');
    return fileResponse(obj, signed ? signedName(d.filename) : d.filename, req, env, url.searchParams.get('dl') !== '1');
  }
  if ((m = p.match(/^\/api\/docs\/([^/]+)\/return$/)) && M === 'POST') {
    const u = await authUser(req, env); const d = await ownDoc(env, u, m[1]); const x = await body(req);
    if (d.status !== 'signed') throw new HttpError(409, '這份文件還沒簽名，不需要退回');
    const reason = String(x.reason || '').slice(0, 500);
    await env.DB.prepare("UPDATE docs SET status = 'returned', signed_key = NULL, signed_size = NULL, signed_at = NULL, return_reason = ? WHERE id = ?").bind(reason, d.id).run();
    if (d.signed_key) await env.FILES.delete(d.signed_key);
    return J({ ok: true, sign_url: signUrl(env, d.token, req) });
  }

  /* ---------- 付款（綠界） ---------- */
  if (p === '/api/pay/create' && M === 'POST') {
    const u = await authUser(req, env); const { plan } = await body(req); const pl = plans(env)[plan];
    if (!pl || !(pl.price > 0)) throw new HttpError(400, '沒有這個方案');
    if (!env.ECPAY_MERCHANT_ID || !env.ECPAY_HASH_KEY) throw new HttpError(503, '付款功能尚未設定');
    const tradeNo = ('P' + now().toString(36) + randId(6).replace(/[^A-Za-z0-9]/g, '')).toUpperCase().slice(0, 20);
    const api = (env.API_URL || url.origin).replace(/\/$/, ''); const site = siteBase(env, req);
    const f = {
      MerchantID: env.ECPAY_MERCHANT_ID, MerchantTradeNo: tradeNo, MerchantTradeDate: ecpayDate(), PaymentType: 'aio',
      TotalAmount: String(pl.price), TradeDesc: (env.SITE_NAME || 'PDF').slice(0, 50), ItemName: pl.name.slice(0, 200),
      ReturnURL: api + '/api/pay/notify', ChoosePayment: pl.pay || env.ECPAY_CHOOSE_PAYMENT || 'ALL', EncryptType: '1',
      ClientBackURL: site + '/account.html?order=' + tradeNo, CustomField1: plan
    };
    // 小額方案只收信用卡；其他方案排除手續費固定、對小額不划算的付款方式（例如超商代碼一筆 31 元）
    if (f.ChoosePayment === 'ALL' && env.ECPAY_IGNORE_PAYMENT) f.IgnorePayment = env.ECPAY_IGNORE_PAYMENT;
    f.CheckMacValue = await ecpayMac(f, env);
    await env.DB.prepare("INSERT INTO orders (trade_no, uid, email, plan, amount, days, credits, credit_days, status, created_at) VALUES (?,?,?,?,?,?,?,?, 'created', ?)")
      .bind(tradeNo, u.uid, u.email, plan, pl.price, pl.pro_days || pl.days || 0, pl.credits || 0, pl.credit_days || 0, now()).run();
    const action = env.ECPAY_STAGE === 'on' ? 'https://payment-stage.ecpay.com.tw/Cashier/AioCheckOut/V5' : 'https://payment.ecpay.com.tw/Cashier/AioCheckOut/V5';
    return J({ action, fields: f, trade_no: tradeNo });
  }
  if (p === '/api/pay/notify' && M === 'POST') {
    const text = (s, st = 200) => new Response(s, { status: st, headers: { 'Content-Type': 'text/plain' } });
    const form = await req.formData(); const x = {}; for (const [k, v] of form.entries()) x[k] = String(v);
    const mac = await ecpayMac(x, env);
    if (!x.CheckMacValue || !timingSafeEq(mac, String(x.CheckMacValue).toUpperCase())) return text('0|CheckMacValue Error');
    if (x.MerchantID !== env.ECPAY_MERCHANT_ID) return text('0|MerchantID Error');
    const o = await env.DB.prepare('SELECT * FROM orders WHERE trade_no = ?').bind(x.MerchantTradeNo).first();
    if (!o) return text('0|Order Not Found');
    if (o.status === 'paid') return text('1|OK');                                     // 綠界可能重送，已處理過就直接回 OK
    const simulated = x.SimulatePaid === '1' && env.ECPAY_STAGE !== 'on';               // 正式環境不接受「模擬付款」
    if (x.RtnCode === '1' && +x.TradeAmt === +o.amount && !simulated) {
      // 先把訂單改成已付款；只有真的改到（第一次收到通知）才加天數和份數，重送的通知不會重複加
      const r = await env.DB.prepare("UPDATE orders SET status = 'paid', paid_at = ?, ecpay_trade_no = ?, payment_type = ? WHERE trade_no = ? AND status != 'paid'").bind(now(), x.TradeNo || '', x.PaymentType || '', o.trade_no).run();
      if (r.meta.changes) await env.DB.batch(grantStmts(env, o.uid, { pro_days: o.days, credits: o.credits, credit_days: o.credit_days }, 'order', o.trade_no));
    } else if (['2', '800', '10100073'].includes(String(x.RtnCode))) {
      await env.DB.prepare('UPDATE orders SET note = ? WHERE trade_no = ?').bind(`等待付款（${x.PaymentType || ''} ${x.RtnMsg || ''}）`.slice(0, 300), o.trade_no).run();   // ATM 取號成功等，還沒付款
    } else {
      await env.DB.prepare("UPDATE orders SET status = 'failed', ecpay_trade_no = ?, note = ? WHERE trade_no = ? AND status != 'paid'").bind(x.TradeNo || '', `RtnCode=${x.RtnCode} ${x.RtnMsg || ''} ${simulated ? '(simulated)' : ''}`.slice(0, 300), o.trade_no).run();
    }
    return text('1|OK');
  }
  if (p === '/api/pay/orders' && M === 'GET') {
    const u = await authUser(req, env);
    const { results } = await env.DB.prepare('SELECT trade_no, plan, amount, days, credits, status, created_at, paid_at, payment_type FROM orders WHERE uid = ? ORDER BY created_at DESC LIMIT 50').bind(u.uid).all();
    const pl = plans(env);
    return J({ orders: results.map(o => ({ ...o, plan_name: (pl[o.plan] && pl[o.plan].name) || o.plan })) });
  }
  /* 學校匯款、開發票等不走綠界的訂單：網站管理者手動開通 */
  if (p === '/api/admin/grant' && M === 'POST') {
    const u = await authUser(req, env); if (!isSiteAdmin(u, env)) throw new HttpError(403, '只有網站管理者可以開通');
    const x = await body(req); const email = normEmail(x.email);
    const credits = Math.max(0, Math.min(100000, parseInt(x.credits, 10) || 0)), pro_days = Math.max(0, Math.min(3660, parseInt(x.pro_days, 10) || 0));
    const credit_days = Math.max(1, Math.min(1100, parseInt(x.credit_days, 10) || 365));
    if (!credits && !pro_days) throw new HttpError(400, '請填份數或進階版天數');
    const t = await env.DB.prepare('SELECT uid FROM users WHERE email = ? ORDER BY last_seen DESC LIMIT 1').bind(email).first();
    if (!t) throw new HttpError(404, '找不到這個帳號，請對方先用這個 Google 帳號登入網站一次');
    await env.DB.batch(grantStmts(env, t.uid, { credits, pro_days, credit_days }, 'admin:' + u.email, String(x.note || '').slice(0, 200)));
    return J({ ok: true, account: await account({ uid: t.uid, email, name: '' }, env) });
  }

  /* ---------- 網站管理者：用量監控 ---------- */
  if (p === '/api/admin/stats' && M === 'GET') {
    const u = await authUser(req, env); if (!isSiteAdmin(u, env)) throw new HttpError(403, '只有網站管理者可以查看');
    return J(await siteStats(env));
  }
  throw new HttpError(404, '找不到這個功能');
}
function signedName(fn) { return fn.replace(/(\.pdf)?$/i, '(已簽).pdf'); }

/* ============================== 用量統計與排程 ============================== */
async function siteStats(env) {
  const one = async (sql, ...a) => (await env.DB.prepare(sql).bind(...a).first()) || {};
  const users = await one('SELECT COUNT(*) AS n, SUM(CASE WHEN paid_until > ? THEN 1 ELSE 0 END) AS paid, SUM(CASE WHEN last_seen > ? THEN 1 ELSE 0 END) AS active30 FROM users', now(), now() - 30 * DAY);
  const files = await one('SELECT COUNT(*) AS docs, COALESCE(SUM(orig_size),0) + COALESCE(SUM(signed_size),0) AS bytes, SUM(CASE WHEN status = \'signed\' THEN 1 ELSE 0 END) AS signed FROM docs');
  const batches = await one('SELECT COUNT(*) AS n FROM batches');
  const sales = await one("SELECT COUNT(*) AS n, COALESCE(SUM(amount),0) AS amount FROM orders WHERE status = 'paid' AND paid_at >= ?", twMonthStart());
  const usage = (await env.DB.prepare('SELECT feature, COUNT(*) AS n FROM usage WHERE created_at >= ? GROUP BY feature').bind(now() - 30 * DAY).all()).results;
  const split = await one("SELECT COALESCE(SUM(CASE WHEN b.trial = 1 THEN COALESCE(d.orig_size,0) + COALESCE(d.signed_size,0) END),0) AS trial_bytes FROM docs d JOIN batches b ON b.id = d.batch_id");
  const credits = await one('SELECT COALESCE(SUM(doc_credits),0) AS open_credits, SUM(CASE WHEN credits_until > ? AND doc_credits > 0 THEN 1 ELSE 0 END) AS buyers FROM users WHERE credits_until > ?', now(), now());
  const storageLimit = intVar(env, 'R2_FREE_GB', 10) * 1073741824; const guard = intVar(env, 'TRIAL_STORAGE_GUARD_GB', 8) * 1073741824;
  const overGB = Math.max(0, files.bytes - storageLimit) / 1073741824;
  const warn = [];
  if (files.bytes > storageLimit * 0.8) warn.push(`檔案空間已用 ${(files.bytes / 1073741824).toFixed(2)} GB，超過免費額度（${env.R2_FREE_GB || 10} GB）的 80%${overGB > 0 ? `；超出 ${overGB.toFixed(1)} GB，約每月 US$ ${(Math.ceil(overGB) * 0.015).toFixed(2)}` : ''}`);
  if (guard > 0 && files.bytes > guard) warn.push(`總空間超過試用警戒線（${env.TRIAL_STORAGE_GUARD_GB || 8} GB），免費試用的新上傳已暫停，付費客戶不受影響`);
  return { users, files: { ...files, ...split, limit_bytes: storageLimit, trial_guard_bytes: guard, over_gb: overGB }, credits, batches, sales_this_month: sales, usage_30d: usage, warnings: warn, time: now() };
}
async function cron(env) {
  await ensureSchema(env);
  // 1) 刪除超過保存期限的批次（個資最小化）。快到期的批次會在管理頁上顯示提醒，不寄信
  const { results } = await env.DB.prepare('SELECT * FROM batches WHERE retain_until < ? LIMIT 50').bind(now()).all();
  for (const b of results) { try { await deleteBatch(env, b); } catch (e) { console.error('purge', b.id, e); } }
}

/* ============================== 自動建立資料表 ============================== */
// 跟 schema.sql 一樣；第一次連線時自動執行（都是 IF NOT EXISTS，重複執行沒關係）
const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS users (uid TEXT PRIMARY KEY, email TEXT, name TEXT, paid_until INTEGER, doc_credits INTEGER DEFAULT 0, credits_until INTEGER, trial_docs INTEGER DEFAULT 0, created_at INTEGER, last_seen INTEGER)`,
  `CREATE TABLE IF NOT EXISTS usage (id INTEGER PRIMARY KEY AUTOINCREMENT, uid TEXT NOT NULL, feature TEXT NOT NULL, trial INTEGER NOT NULL, created_at INTEGER)`,
  `CREATE INDEX IF NOT EXISTS idx_usage_uid ON usage(uid, feature, trial)`,
  `CREATE INDEX IF NOT EXISTS idx_usage_time ON usage(created_at)`,
  `CREATE TABLE IF NOT EXISTS batches (id TEXT PRIMARY KEY, owner_uid TEXT NOT NULL, name TEXT, org_name TEXT, message TEXT, deadline INTEGER, require_login INTEGER DEFAULT 1, retain_until INTEGER, created_at INTEGER, trial INTEGER DEFAULT 0, warned INTEGER DEFAULT 0)`,
  `CREATE INDEX IF NOT EXISTS idx_batches_owner ON batches(owner_uid)`,
  `CREATE INDEX IF NOT EXISTS idx_batches_retain ON batches(retain_until)`,
  `CREATE TABLE IF NOT EXISTS docs (id TEXT PRIMARY KEY, batch_id TEXT NOT NULL, owner_uid TEXT NOT NULL, filename TEXT, student_id TEXT, student_name TEXT, email TEXT, token TEXT UNIQUE NOT NULL, status TEXT NOT NULL, orig_key TEXT, orig_size INTEGER, signed_key TEXT, signed_size INTEGER, sent_at INTEGER, sent_count INTEGER DEFAULT 0, signed_at INTEGER, signed_ip TEXT, signed_email TEXT, return_reason TEXT, created_at INTEGER, credit TEXT)`,
  `CREATE INDEX IF NOT EXISTS idx_docs_batch ON docs(batch_id)`,
  `CREATE TABLE IF NOT EXISTS orders (trade_no TEXT PRIMARY KEY, uid TEXT NOT NULL, email TEXT, plan TEXT, amount INTEGER, days INTEGER, credits INTEGER DEFAULT 0, credit_days INTEGER DEFAULT 0, status TEXT, created_at INTEGER, paid_at INTEGER, ecpay_trade_no TEXT, payment_type TEXT, note TEXT)`,
  `CREATE INDEX IF NOT EXISTS idx_orders_uid ON orders(uid)`,
  `CREATE TABLE IF NOT EXISTS credit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, uid TEXT NOT NULL, credits INTEGER, pro_days INTEGER, reason TEXT, ref TEXT, created_at INTEGER)`,
  `CREATE INDEX IF NOT EXISTS idx_credit_uid ON credit_log(uid)`
];
let schemaReady = null;
function ensureSchema(env) {
  if (!schemaReady) schemaReady = env.DB.batch(SCHEMA.map(q => env.DB.prepare(q))).catch(e => { schemaReady = null; throw e; });
  return schemaReady;
}

export default {
  async fetch(req, env, ctx) {
    const path = new URL(req.url).pathname;
    // 不是 /api/ 開頭的，就是網頁（web 資料夾裡的檔案）
    if (!path.startsWith('/api/') && path !== '/api' && env.ASSETS) return env.ASSETS.fetch(req);
    try { await ensureSchema(env); return await route(req, env, ctx); }
    catch (e) {
      if (e instanceof HttpError) return json({ error: e.message, ...e.extra }, e.status, req, env);
      console.error(e); return json({ error: '伺服器發生錯誤，請稍後再試' }, 500, req, env);
    }
  },
  async scheduled(event, env, ctx) { ctx.waitUntil(cron(env)); }
};
export { ecpayMac, ecpayEncode };
