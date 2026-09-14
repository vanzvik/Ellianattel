const COOKIE = 'ellia_gate';
const MSG = 'ellia-gate';

async function token(pin) {
    const key = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(pin),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(MSG));
    return Array.from(new Uint8Array(sig), function (b) {
        return b.toString(16).padStart(2, '0');
    }).join('');
}

export const config = {
    matcher: ['/((?!api/unlock|api/session|pin.html).*)']
};

export default async function middleware(request) {
    const pin = process.env.SITE_PIN || '';
    if (!pin) {
        return new Response('Unavailable', { status: 503 });
    }
    const raw = request.headers.get('cookie') || '';
    const m = /(?:^|;\s*)ellia_gate=([0-9a-f]+)/.exec(raw);
    if (m && m[1] === await token(pin)) {
        return;
    }
    return Response.redirect(new URL('/pin.html', request.url), 302);
}
