const crypto = require('crypto');

const MSG = 'ellia-gate';

function token(pin) {
    return crypto.createHmac('sha256', String(pin)).update(MSG).digest('hex');
}

module.exports = function handler(req, res) {
    const pin = process.env.SITE_PIN || '';
    const raw = req.headers.cookie || '';
    const m = /(?:^|;\s*)ellia_gate=([0-9a-f]+)/.exec(raw);
    const ok = !!(pin && m && m[1] === token(pin));
    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ ok: ok }));
};
