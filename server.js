// Community Scam Map - server (Node.js, no npm dependencies)
// Why Node stdlib only? So Render / any free host can run it with
// just `node server.js`, no install step to fail on judging day.
// Data is kept in memory + data.json in the same folder, so a licence
// renewal (POST /license) never deletes old reports - it only flips
// the licence flag. A restart keeps data.json; /admin/reset is the
// only thing that deletes reports, exactly as the PRD requires.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const DATA_FILE = path.join(ROOT, 'data.json');
const LICENSE_FILE = path.join(ROOT, 'license.json');

// Public key only. The matching private key is NOT in this repo
// (see .gitignore). It is used only by tools/sign-license.js on the
// team laptop to sign a licence file. Anyone who edits expires_at
// without that private key produces a signature that fails here.
const PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAlIDJjViMXOvmx6G464paTEd7TJA6dYjISwzj34bP5zI=
-----END PUBLIC KEY-----`;

// ---- Appendix B: the 25 test areas, with their fixed map points ----
// Why fixed points? So the map never shows a reporter's own location.
// Every cluster uses the area point below, never a report's GPS.
const AREAS = {
  '560102': { locality: 'HSR Layout', city: 'Bengaluru', lat: 12.9116, lng: 77.6473 },
  '560038': { locality: 'Indiranagar', city: 'Bengaluru', lat: 12.9784, lng: 77.6408 },
  '560034': { locality: 'Koramangala', city: 'Bengaluru', lat: 12.9352, lng: 77.6245 },
  '560066': { locality: 'Whitefield', city: 'Bengaluru', lat: 12.9698, lng: 77.75 },
  '560076': { locality: 'BTM Layout', city: 'Bengaluru', lat: 12.9166, lng: 77.6101 },
  '560011': { locality: 'Jayanagar', city: 'Bengaluru', lat: 12.9299, lng: 77.5826 },
  '560037': { locality: 'Marathahalli', city: 'Bengaluru', lat: 12.9591, lng: 77.6974 },
  '560103': { locality: 'Bellandur', city: 'Bengaluru', lat: 12.926, lng: 77.6762 },
  '560100': { locality: 'Electronic City', city: 'Bengaluru', lat: 12.8452, lng: 77.6602 },
  '560078': { locality: 'JP Nagar', city: 'Bengaluru', lat: 12.9077, lng: 77.5851 },
  '560003': { locality: 'Malleshwaram', city: 'Bengaluru', lat: 13.0035, lng: 77.5709 },
  '560010': { locality: 'Rajajinagar', city: 'Bengaluru', lat: 12.9915, lng: 77.552 },
  '560024': { locality: 'Hebbal', city: 'Bengaluru', lat: 13.0358, lng: 77.597 },
  '560064': { locality: 'Yelahanka', city: 'Bengaluru', lat: 13.1007, lng: 77.5963 },
  '560070': { locality: 'Banashankari', city: 'Bengaluru', lat: 12.925, lng: 77.5468 },
  '400050': { locality: 'Bandra West', city: 'Mumbai', lat: 19.0596, lng: 72.8295 },
  '110016': { locality: 'Hauz Khas', city: 'Delhi', lat: 28.5494, lng: 77.2001 },
  '500081': { locality: 'Madhapur', city: 'Hyderabad', lat: 17.4486, lng: 78.3908 },
  '600020': { locality: 'Adyar', city: 'Chennai', lat: 13.0012, lng: 80.2565 },
  '411014': { locality: 'Viman Nagar', city: 'Pune', lat: 18.5679, lng: 73.9143 },
  '700091': { locality: 'Salt Lake Sector V', city: 'Kolkata', lat: 22.579, lng: 88.429 },
  '380015': { locality: 'Satellite', city: 'Ahmedabad', lat: 23.026, lng: 72.5085 },
  '302017': { locality: 'Malviya Nagar', city: 'Jaipur', lat: 26.857, lng: 75.808 },
  '226010': { locality: 'Gomti Nagar', city: 'Lucknow', lat: 26.854, lng: 80.999 },
  '682030': { locality: 'Kakkanad', city: 'Kochi', lat: 10.0159, lng: 76.3419 },
};

// ---- Appendix C: verified numbers (normalised form -> name) ----
const VERIFIED = {
  '1930': 'National Cybercrime Helpline',
  '1909': 'TRAI Do Not Disturb',
  '18001600': 'HDFC Bank customer care',
  '18002600': 'HDFC Bank customer care',
  '18001080': 'ICICI Bank customer care',
  '18001234': 'State Bank of India customer care',
  '18002100': 'State Bank of India customer care',
  '18604195555': 'Axis Bank customer care',
  '18602662666': 'Kotak Mahindra Bank customer care',
  'HDFCBK': 'HDFC Bank SMS sender',
  'ICICIB': 'ICICI Bank SMS sender',
  'SBIINB': 'State Bank of India SMS sender',
  'AXISBK': 'Axis Bank SMS sender',
  'KOTAKB': 'Kotak Mahindra Bank SMS sender',
  'https://cybercrime.gov.in': 'National Cyber Crime Reporting Portal',
  'https://sancharsaathi.gov.in': 'Sanchar Saathi',
  '+918041002233': 'Fresh Bakes, Indiranagar',
  '+918025530190': 'Koramangala Pharmacy',
  'freshbakes@okaxis': 'Fresh Bakes, Indiranagar',
};

// ---- State ----
let db = { reports: [], challenges: [], lastSeenMs: 0 };
try { const raw = fs.readFileSync(DATA_FILE, 'utf8'); const p = JSON.parse(raw); if (Array.isArray(p.reports)) db = p; } catch (e) {}
let license = null;
try { license = JSON.parse(fs.readFileSync(LICENSE_FILE, 'utf8')); } catch (e) {}
function saveDb() { try { fs.writeFileSync(DATA_FILE, JSON.stringify(db)); } catch (e) {} }
function saveLicense() { try { fs.writeFileSync(LICENSE_FILE, JSON.stringify(license, null, 2)); } catch (e) {} }

// ---- Normalisation: one identifier, many ways of typing it ----
function normalizePhone(v) {
  if (typeof v !== 'string') return null;
  let d = v.trim().replace(/[\s\-()]/g, '');
  if (d.startsWith('+')) d = d.slice(1);
  if (d.startsWith('91') && d.length === 12) d = d.slice(2);
  else if (d.startsWith('0') && d.length === 11) d = d.slice(1);
  if (d === '1930' || d === '1909') return d;
  if (/^1800\d{4,6}$/.test(d)) return d;
  if (/^1860\d{7}$/.test(d)) return d;
  if (/^[6-9]\d{9}$/.test(d)) return '+91' + d;
  return null;
}
function normalizeUpi(v) {
  if (typeof v !== 'string') return null;
  const s = v.trim().toLowerCase().replace(/\s+/g, '');
  return /^[a-z0-9._-]{2,30}@[a-z0-9]{2,20}$/.test(s) ? s : null;
}
function normalizeUrl(v) {
  if (typeof v !== 'string') return null;
  let s = v.trim().toLowerCase();
  s = s.replace(/^https?:\/\//, '').replace(/^www\./, '');
  s = s.split('?')[0].split('#')[0].replace(/\/+$/, '');
  if (!/^[a-z0-9.-]+\.[a-z]{2,}(\/[^\s]*)?$/.test(s)) return null;
  return 'https://' + s;
}
function normalizeSender(v) {
  if (typeof v !== 'string') return null;
  let s = v.trim().toUpperCase().replace(/^([A-Z]{2})-/, '');
  return /^[A-Z0-9]{6}$/.test(s) ? s : null;
}
function normalize(type, value) {
  if (type === 'phone') return normalizePhone(value);
  if (type === 'upi') return normalizeUpi(value);
  if (type === 'url') return normalizeUrl(value);
  if (type === 'sender_id') return normalizeSender(value);
  return null;
}
function maskValue(type, v) {
  if (type === 'phone') {
    if (v.length === 10) return v.slice(0, 2) + 'XXXXX' + v.slice(-3);
    if (v.startsWith('+91')) { const d = v.slice(3); return '+91 ' + d.slice(0, 2) + 'XXXXX' + d.slice(-3); }
    return v.slice(0, 2) + '****' + v.slice(-2);
  }
  if (type === 'upi') { const [u, dom] = v.split('@'); return (u[0] || 'r') + '***@' + dom; }
  if (type === 'url') {
    const rest = v.replace('https://', '');
    const slash = rest.indexOf('/');
    const host = slash === -1 ? rest : rest.slice(0, slash);
    const p = slash === -1 ? '' : rest.slice(slash);
    const dot = host.indexOf('.');
    const first = dot === -1 ? host : host.slice(0, dot);
    const tail = dot === -1 ? '' : host.slice(dot);
    return first.slice(0, 3) + '***' + tail + (p ? '/...' : '');
  }
  if (type === 'sender_id') return v.slice(0, 2) + '****';
  return v;
}
function normNote(n) {
  return (n || '').toLowerCase().replace(/[^a-z0-9\u0900-\u097F ]/g, ' ').replace(/\s+/g, ' ').trim();
}
function parseTime(s) { const t = Date.parse(s); return Number.isNaN(t) ? null : t; }

// ---- Trust rules: why each rule exists is in README + PDF ----
// 1) Same reporter_id for one identifier = 1 person, however many times.
// 2) Same ip_prefix for one identifier = 1 connection (stops 22 fake
//    accounts on one Wi-Fi). 3) Same exact description = 1 copied text
//    (stops a copy-pasted report-bomb). Real, unrelated victims differ
//    on at least one of these, so a real wave still passes. Empty notes
//    are NOT collapsed by text, so real reports with no note still count.
function trustedReports(reports, groupBy) {
  const sorted = [...reports].sort((a, b) => a.occurredMs - b.occurredMs);
  const seen = new Map(); // groupKey -> {reporters, ips, notes}
  const out = [];
  for (const r of sorted) {
    const g = groupBy(r);
    if (!seen.has(g)) seen.set(g, { reporters: new Set(), ips: new Set(), notes: new Set() });
    const s = seen.get(g);
    if (s.reporters.has(r.reporter_id)) continue;
    if (r.ip_prefix && s.ips.has(r.ip_prefix)) continue;
    const nn = normNote(r.note);
    if (nn && s.notes.has(nn)) continue;
    s.reporters.add(r.reporter_id);
    if (r.ip_prefix) s.ips.add(r.ip_prefix);
    if (nn) s.notes.add(nn);
    out.push(r);
  }
  return out;
}
function haversineKm(a, b) {
  const R = 6371, toRad = d => d * Math.PI / 180;
  const dLat = toRad(b.lat - a.lat), dLng = toRad(b.lng - a.lng);
  const h = Math.sin(dLat / 2) ** 2 + Math.cos(toRad(a.lat)) * Math.cos(toRad(b.lat)) * Math.sin(dLng / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(h));
}

// ---- Licence ----
function verifySignature(lic) {
  try {
    const key = crypto.createPublicKey(PUBLIC_KEY_PEM);
    return crypto.verify(null, Buffer.from(`${lic.licensee}|${lic.expires_at}`), key, Buffer.from(lic.signature, 'base64'));
  } catch (e) { return false; }
}
function licenseStatus() {
  if (!license || !license.licensee || !license.expires_at || !license.signature) {
    return { licensee: null, expires_at: null, valid: false };
  }
  const exp = parseTime(license.expires_at);
  if (exp === null) return { licensee: license.licensee, expires_at: license.expires_at, valid: false };
  const now = Date.now();
  // Clock-rollback guard: if the clock ever goes backwards by more
  // than 5 minutes from the latest time this server has seen, refuse.
  // Why: otherwise setting the server clock back a year would revive
  // an expired licence. We never move lastSeen backwards.
  if (db.lastSeenMs && now < db.lastSeenMs - 5 * 60 * 1000) {
    return { licensee: license.licensee, expires_at: license.expires_at, valid: false, clock_rollback: true };
  }
  if (now > db.lastSeenMs) { db.lastSeenMs = now; saveDb(); }
  const valid = verifySignature(license) && now <= exp;
  return { licensee: license.licensee, expires_at: license.expires_at, valid };
}

// ---- HTTP helpers ----
function send(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
  res.end(body);
}
function readJson(req) {
  return new Promise(resolve => {
    let data = '';
    req.on('data', c => { data += c; if (data.length > 200000) req.destroy(); });
    req.on('end', () => { try { resolve(data ? JSON.parse(data) : {}); } catch (e) { resolve(null); } });
  });
}
// Simple rate guard: >100 reports in 60s from one reporter or one
// ip_prefix -> 429. The PRD says 429 is not counted against you.
const rate = new Map();
function rateLimited(key) {
  const now = Date.now();
  const arr = (rate.get(key) || []).filter(t => now - t < 60000);
  arr.push(now); rate.set(key, arr);
  return arr.length > 100;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const pathname = url.pathname;
  if (req.method === 'OPTIONS') { res.writeHead(204, { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type' }); return res.end(); }

  // Static frontend: must stay reachable when the licence expires,
  // otherwise the app could not show "Licence expired".
  if (req.method === 'GET' && (pathname === '/' || pathname === '/index.html')) {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    return res.end(fs.readFileSync(path.join(ROOT, 'public', 'index.html')));
  }
  if (req.method === 'GET' && pathname === '/health') return send(res, 200, { ok: true });
  if (req.method === 'GET' && pathname === '/license') { const s = licenseStatus(); return send(res, 200, s); }
  if (req.method === 'POST' && pathname === '/license') {
    const body = await readJson(req);
    if (!body || !body.licensee || !body.expires_at || !body.signature) return send(res, 400, { error: 'licensee, expires_at and signature are required' });
    if (!verifySignature(body)) return send(res, 400, { error: 'INVALID_SIGNATURE' });
    license = { licensee: body.licensee, expires_at: body.expires_at, signature: body.signature };
    saveLicense();
    return send(res, 200, licenseStatus());
  }

  // Every other API request needs a valid licence (PRD: except
  // /health and /license). Data is NOT deleted on expiry.
  const lic = licenseStatus();
  if (!lic.valid) return send(res, 403, { error: 'LICENSE_EXPIRED' });

  if (req.method === 'POST' && pathname === '/admin/reset') {
    db.reports = []; db.challenges = []; saveDb();
    return send(res, 200, { ok: true });
  }
  if (req.method === 'POST' && pathname === '/reports') {
    const b = await readJson(req);
    if (b === null) return send(res, 400, { error: 'invalid JSON' });
    if (b.reporter_id && rateLimited('r:' + b.reporter_id)) return send(res, 429, { error: 'rate limited' });
    if (b.ip_prefix && rateLimited('ip:' + b.ip_prefix)) return send(res, 429, { error: 'rate limited' });
    const norm = normalize(b.identifier_type, b.identifier_value);
    if (!norm) return send(res, 400, { error: 'invalid identifier' });
    if (!b.pincode || !AREAS[String(b.pincode)]) return send(res, 400, { error: 'invalid area code' });
    const occ = parseTime(b.occurred_at);
    if (occ === null) return send(res, 400, { error: 'invalid occurred_at' });
    if (b.report_id && db.reports.some(r => r.report_id === b.report_id)) {
      return send(res, 201, { report_id: b.report_id, case_id: 'CASE-' + String(b.report_id).slice(-6), merged: true });
    }
    const existed = db.reports.some(r => r.identifier_type === b.identifier_type && r.identifier_value_norm === norm);
    const report = {
      report_id: b.report_id || ('rep_' + Date.now()),
      occurred_at: b.occurred_at, occurredMs: occ,
      reported_at: b.reported_at || b.occurred_at,
      reporter_id: b.reporter_id || 'anonymous',
      ip_prefix: b.ip_prefix || '',
      channel: b.channel || 'Something else',
      scam_type: b.scam_type || 'other',
      identifier_type: b.identifier_type, identifier_value_norm: norm,
      pincode: String(b.pincode), locality: AREAS[String(b.pincode)].locality, city: AREAS[String(b.pincode)].city,
      note: b.note || '', has_screenshot: !!b.has_screenshot,
      amount_lost_inr: b.amount_lost_inr || 0,
    };
    db.reports.push(report); saveDb();
    return send(res, 201, { report_id: report.report_id, case_id: 'CASE-' + String(report.report_id).slice(-6), merged: existed });
  }
  if (req.method === 'GET' && pathname === '/lookup') {
    const type = url.searchParams.get('type');
    const value = url.searchParams.get('value');
    const norm = normalize(type, value);
    if (!norm) return send(res, 400, { error: 'invalid identifier' });
    if (VERIFIED[norm] !== undefined) {
      return send(res, 200, { verdict: 'VERIFIED_BUSINESS', report_count: 0, distinct_reporters: 0, first_seen: null, last_seen: null, scam_type: null, display_value: norm, evidence: [], challenged: false, verified_name: VERIFIED[norm] });
    }
    const all = db.reports.filter(r => r.identifier_type === type && r.identifier_value_norm === norm);
    const trusted = trustedReports(all, () => 'lookup');
    const challenged = db.challenges.some(c => c.identifier_type === type && c.identifier_value_norm === norm && c.status === 'under_review');
    let verdict;
    if (trusted.length === 0) verdict = 'NO_REPORTS';
    else if (challenged) verdict = 'SUSPICIOUS';
    else if (trusted.length >= 5) verdict = 'KNOWN_SCAM';
    else verdict = 'SUSPICIOUS';
    const sorted = [...trusted].sort((a, b) => a.occurredMs - b.occurredMs);
    const counts = {};
    for (const r of trusted) counts[r.scam_type] = (counts[r.scam_type] || 0) + 1;
    const topType = Object.keys(counts).sort((a, b) => counts[b] - counts[a])[0] || null;
    return send(res, 200, {
      verdict, report_count: all.length, distinct_reporters: trusted.length,
      first_seen: sorted.length ? sorted[0].occurred_at : null,
      last_seen: sorted.length ? sorted[sorted.length - 1].occurred_at : null,
      scam_type: topType,
      display_value: (trusted.length >= 3 ? norm : maskValue(type, norm)),
      evidence: [...trusted].sort((a, b) => b.occurredMs - a.occurredMs).slice(0, 10).map(r => ({ occurred_at: r.occurred_at, channel: r.channel, scam_type: r.scam_type, pincode: r.pincode })),
      challenged,
    });
  }
  if (req.method === 'GET' && pathname === '/map') {
    const days = parseInt(url.searchParams.get('days') || '7', 10) || 7;
    const radius = parseFloat(url.searchParams.get('radius_km') || '2');
    const pin = url.searchParams.get('pincode');
    if (pin && !AREAS[pin]) return send(res, 400, { error: 'invalid area code' });
    const now = Date.now();
    const from = now - days * 24 * 3600 * 1000;
    const inWindow = db.reports.filter(r => r.occurredMs >= from && r.occurredMs <= now);
    const trusted = trustedReports(inWindow, r => r.identifier_value_norm + '|' + r.pincode);
    const byPin = {};
    for (const r of trusted) { (byPin[r.pincode] = byPin[r.pincode] || []).push(r); }
    const clusters = [];
    for (const [p, list] of Object.entries(byPin)) {
      const area = AREAS[p]; if (!area) continue;
      if (pin) {
        const d = haversineKm(AREAS[pin], area);
        if (d > radius) continue;
      }
      const counts = {};
      for (const r of list) counts[r.scam_type] = (counts[r.scam_type] || 0) + 1;
      const top = Object.keys(counts).sort((a, b) => counts[b] - counts[a])[0];
      clusters.push({ pincode: p, locality: area.locality, city: area.city, count: list.length, top_scam_type: top, severity: list.length >= 10 ? 'CRIT' : list.length >= 4 ? 'HIGH' : 'MED', lat: area.lat, lng: area.lng });
    }
    clusters.sort((a, b) => b.count - a.count);
    return send(res, 200, { clusters });
  }
  if (req.method === 'GET' && pathname === '/alerts') {
    const pin = url.searchParams.get('pincode');
    if (pin && !AREAS[pin]) return send(res, 400, { error: 'invalid area code' });
    const now = Date.now();
    const d24 = 24 * 3600 * 1000;
    const pins = pin ? [pin] : Object.keys(AREAS);
    const alerts = [];
    for (const p of pins) {
      const trusted = trustedReports(db.reports.filter(r => r.pincode === p), r => r.identifier_value_norm + '|' + r.pincode);
      const last24 = trusted.filter(r => r.occurredMs >= now - d24 && r.occurredMs <= now);
      const prior7 = trusted.filter(r => r.occurredMs >= now - 8 * d24 && r.occurredMs < now - d24);
      const baseline = prior7.length / 7;
      if (last24.length >= 5 && last24.length >= 2 * baseline) {
        alerts.push({ type: 'SPIKE', pincode: p, window: '24h', count: last24.length, baseline_per_day: Math.round(baseline * 10) / 10 });
      }
      const prior30Types = new Set(trusted.filter(r => r.occurredMs >= now - 31 * d24 && r.occurredMs < now - d24).map(r => r.scam_type));
      const newTypes = [...new Set(last24.map(r => r.scam_type))].filter(t => !prior30Types.has(t));
      for (const t of newTypes) alerts.push({ type: 'NEW_TYPE', pincode: p, scam_type: t, window: '24h' });
    }
    return send(res, 200, { alerts });
  }
  if (req.method === 'POST' && pathname === '/challenges') {
    const b = await readJson(req);
    if (b === null) return send(res, 400, { error: 'invalid JSON' });
    const norm = normalize(b.identifier_type, b.identifier_value);
    if (!norm) return send(res, 400, { error: 'invalid identifier' });
    const ch = { challenge_id: 'ch_' + Date.now(), status: 'under_review', identifier_type: b.identifier_type, identifier_value_norm: norm, claimant_name: b.claimant_name || '', contact_email: b.contact_email || '', proof_note: b.proof_note || '' };
    db.challenges.push(ch); saveDb();
    return send(res, 201, { challenge_id: ch.challenge_id, status: 'under_review' });
  }
  return send(res, 404, { error: 'not found' });
});
server.listen(PORT, () => console.log('Community Scam Map listening on ' + PORT));
