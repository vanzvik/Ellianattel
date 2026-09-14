const crypto = require('crypto');

const COOKIE = 'ellia_gate';
const MSG = 'ellia-gate';

function token(pin) {
    return crypto.createHmac('sha256', String(pin)).update(MSG).digest('hex');
}

function equal(a, b) {
    const aa = Buffer.from(String(a), 'utf8');
    const bb = Buffer.from(String(b), 'utf8');
    if (aa.length !== bb.length) return false;
    return crypto.timingSafeEqual(aa, bb);
}

module.exports = async function handler(req, res) {
    if (req.method !== 'POST') {
        res.statusCode = 405;
        res.end();
        return;
    }
    const pin = process.env.SITE_PIN || '';
    if (!pin) {
        res.statusCode = 503;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ ok: false }));
        return;
    }
    let body = req.body;
    if (typeof body === 'string') {
        try { body = JSON.parse(body); } catch (e) { body = {}; }
    }
    if (!body || typeof body !== 'object') body = {};
    const given = body.pin != null ? String(body.pin).trim() : '';
    if (!equal(given, pin)) {
        res.statusCode = 401;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ ok: false }));
        return;
    }
    const secure = process.env.VERCEL ? '; Secure' : '';
    res.setHeader(
        'Set-Cookie',
        COOKIE + '=' + token(pin) + '; HttpOnly; Path=/; SameSite=Lax; Max-Age=31536000' + secure
    );
    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ ok: true }));
};
