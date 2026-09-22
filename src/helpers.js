import crypto from 'crypto';
import fetch from 'node-fetch';
import { DEVICE, APP, UA_NATIVE } from './config.js';
import { computeTokenSnMac, computeXSign } from './crypto.js';

// ─── Utilities ───

export const generateUUID = () => crypto.randomUUID().toUpperCase();

export const nowISO = () => {
  const d = new Date();
  const off = -d.getTimezoneOffset();
  const sign = off >= 0 ? '+' : '-';
  const hh = String(Math.floor(Math.abs(off) / 60)).padStart(2, '0');
  const mm = String(Math.abs(off) % 60).padStart(2, '0');
  return (
    d
      .toISOString()
      .replace('Z', '')
      .replace(/\.\d{3}/, `.${String(d.getMilliseconds()).padStart(3, '0')}`) +
    sign +
    hh +
    mm
  );
};

// ─── Cookie builder ───

export const entranceCookie = (extraUserToken) => {
  let c = `deviceId=${DEVICE.deviceId}; installId=${DEVICE.installId}; is_mobile_app=true; locale=${APP.locale}; ma_bld=${APP.build}; ma_platform_type=${APP.platform}; ma_platform_ver=${APP.platformVer}; ma_ver=${APP.version}; pk=${DEVICE.pk}; pkTag=${DEVICE.pkTag}; xs=R:0|E:0|RH:0|N:0`;
  if (extraUserToken) c += `; user_token=${extraUserToken}`;
  return c;
};

// ─── Extract user_token from set-cookie ───

export const extractUserToken = (resp) => {
  const raw = resp.headers.raw()['set-cookie'] || [];
  for (const c of raw) {
    const m = c.match(/user_token=([^;]+)/);
    if (m) return m[1];
  }
  return null;
};

// ─── Logged fetch wrapper ───

/* ── Логи исходящих вызовов Kaspi ────────────────────────────────────────
   Раньше сюда сваливались заголовки целиком (Cookie, X-Sign, X-Kb-TokenSn),
   тела запросов (номер телефона, код из SMS, подписанные payload-ы) и ответы
   с tokenSN и vtokenSecret. Всё это оседало в `docker logs` открытым текстом:
   кто дотянулся до логов — получил живые сессии мерчантов.

   При этом именно по этим логам ищутся причины сбоев онбординга, поэтому
   диагностика оставлена: шаг, код экрана и текст ошибки Kaspi не секретны.

   KASPI_LOG=meta (по умолчанию) — метод, адрес, статус и разбор ответа.
   KASPI_LOG=full — то же плюс тела и заголовки, но с вырезанными секретами.
   KASPI_LOG=off  — молчать.                                              */

const LOG_MODE = (process.env.KASPI_LOG || 'meta').toLowerCase();

const SECRET_HEADERS = new Set([
  'cookie', 'set-cookie', 'authorization',
  'x-kb-tokensn', 'x-kb-tokensnmac', 'x-sign', 'x-su', 'x-pktag',
]);

// Ключи, значения которых нельзя печатать ни при каких настройках.
const SECRET_KEY = /^(otp|userotp|tokensn|vtokensecret|secret|sign|signed|pinhash|x509|pk|usertoken|password|guard)$/i;

const maskPhone = (v) =>
  typeof v === 'string' && /^\+?\d{10,}$/.test(v) ? v.slice(0, 4) + '****' + v.slice(-2) : v;

function redact(value, key) {
  if (key && SECRET_KEY.test(key)) return '«скрыто»';
  if (Array.isArray(value)) return value.map((v) => redact(v));
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = redact(v, k);
    return out;
  }
  if (key && /phone/i.test(key)) return maskPhone(value);
  return value;
}

function redactHeaders(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) {
    out[k] = SECRET_HEADERS.has(k.toLowerCase()) ? '«скрыто»' : v;
  }
  return out;
}

/** Короткий разбор ответа Kaspi: то, по чему ищут причину сбоя. */
function summarize(body) {
  if (!body || typeof body !== 'object') return null;
  const bits = [];
  if (body.meta?.sn) bits.push('шаг=' + body.meta.sn);
  if (body.view?.code) bits.push('экран=' + body.view.code);
  if (body.data?.type) bits.push('тип=' + body.data.type);
  if (body.error?.code) bits.push('ошибка=' + body.error.code);
  if (body.error?.desc) bits.push('текст="' + body.error.desc + '"');
  if (body.success !== undefined) bits.push('success=' + body.success);
  return bits.length ? bits.join(' · ') : null;
}

export const loggedFetch = async (url, options = {}) => {
  const method = (options.method || 'GET').toUpperCase();
  const quiet = LOG_MODE === 'off';

  if (!quiet) console.log(`\n>>> ${method} ${url}`);
  if (LOG_MODE === 'full') {
    if (options.headers) console.log('>>> Headers:', JSON.stringify(redactHeaders(options.headers), null, 2));
    if (options.body) {
      let parsed;
      try { parsed = redact(JSON.parse(options.body)); } catch { parsed = '«нечитаемое тело»'; }
      console.log('>>> Body:', JSON.stringify(parsed, null, 2));
    }
  }

  const resp = await fetch(url, options);
  const cloned = resp.clone();
  let body;
  try {
    body = await cloned.json();
  } catch {
    try {
      body = await cloned.text();
    } catch {
      body = '[unreadable]';
    }
  }

  if (!quiet) {
    console.log(`<<< ${resp.status} ${resp.statusText}`);
    const short = summarize(body);
    if (short) console.log('<<<', short);
    if (LOG_MODE === 'full') {
      const safe = typeof body === 'object' ? JSON.stringify(redact(body), null, 2) : body;
      console.log('<<< Response:', safe);
    }
  }
  return resp;
};

export const __redactForTests = { redact, redactHeaders, summarize };

// ─── Signed QR-pay headers (session passed as parameter) ───

export const signedQrPayHeaders = (url, session, body) => {
  const xsh =
    'url,X-Install-ID,X-PI,X-App-Bld,X-Platform-Ver,X-Locale,X-App-Ver,X-Device-ID,X-SV,X-Time,X-Platform-Type,X-Call,X-Kb-TokenSnMac,X-Kb-TokenSn';
  const headers = {
    'X-Kb-TokenSn': session.tokenSN,
    'X-Kb-TokenSnMac': computeTokenSnMac(session.tokenSN, session.decryptedSecret),
    'X-PI': session.profileId != null ? String(session.profileId) : '',
    'X-Install-ID': DEVICE.installId,
    'X-Device-ID': DEVICE.deviceId,
    'X-App-Ver': APP.version,
    'X-App-Bld': APP.build,
    'X-Platform-Type': APP.platform,
    'X-Platform-Ver': APP.platformVer,
    'X-Locale': APP.locale,
    'X-Time': nowISO(),
    'X-Request-ID': generateUUID(),
    'X-Call': 'notConnected',
    'X-SV': '2',
    'X-SH': xsh,
    'User-Agent': UA_NATIVE,
    Accept: '*/*',
    'Accept-Language': 'ru',
    'Accept-Encoding': 'gzip, deflate, br',
  };
  headers['X-Sign'] = computeXSign(url, headers, xsh, body);
  return headers;
};
