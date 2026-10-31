// Sign a licence file with the PRIVATE key (kept on the laptop, never in git).
// Usage:
//   node tools/sign-license.js --licensee "Demo Bank" --minutes 5 --key license-private-key.pem --out licence-5min.json
//   node tools/sign-license.js --licensee "Demo Bank" --expires "2027-12-31T23:59:00+05:30" --key license-private-key.pem --out licence-long.json
// The server verifies with the public key built into server.js.
// If expires_at is edited by hand, the signature no longer matches and
// the server returns 400 INVALID_SIGNATURE on upload.
const crypto = require('crypto');
const fs = require('fs');
function arg(name) { const i = process.argv.indexOf(name); return i === -1 ? null : process.argv[i + 1]; }
const licensee = arg('--licensee') || 'Demo Bank';
const keyFile = arg('--key') || 'license-private-key.pem';
let expires_at = arg('--expires');
if (!expires_at) {
  const mins = parseInt(arg('--minutes') || '5', 10);
  const d = new Date(Date.now() + mins * 60000);
  // Format with +05:30 like the PRD example
  const pad = n => String(n).padStart(2, '0');
  const off = '+05:30';
  const local = new Date(d.getTime() + 5.5 * 3600 * 1000);
  expires_at = `${local.getUTCFullYear()}-${pad(local.getUTCMonth() + 1)}-${pad(local.getUTCDate())}T${pad(local.getUTCHours())}:${pad(local.getUTCMinutes())}:${pad(local.getUTCSeconds())}${off}`;
}
const priv = crypto.createPrivateKey(fs.readFileSync(keyFile, 'utf8'));
const sig = crypto.sign(null, Buffer.from(`${licensee}|${expires_at}`), priv).toString('base64');
const out = { licensee, expires_at, signature: sig };
fs.writeFileSync(arg('--out') || 'licence.json', JSON.stringify(out, null, 2));
console.log(JSON.stringify(out, null, 2));
