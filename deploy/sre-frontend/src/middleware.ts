import { NextRequest, NextResponse } from 'next/server';

const AUTH_SECRET = process.env.AUTH_SECRET || '';

function base64urlDecode(str: string): string {
  const padded = str + '='.repeat((4 - str.length % 4) % 4);
  return Buffer.from(padded, 'base64url').toString('utf-8');
}

async function hmacSha256Hex(secret: string, message: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function verifyToken(token: string): Promise<string | null> {
  if (!AUTH_SECRET) return null;
  try {
    const dot = token.indexOf('.');
    if (dot === -1) return null;
    const payloadB64 = token.substring(0, dot);
    const sig = token.substring(dot + 1);
    const expected = await hmacSha256Hex(AUTH_SECRET, payloadB64);
    if (sig !== expected) return null;
    const payload = JSON.parse(base64urlDecode(payloadB64));
    if (payload.e < Date.now() / 1000) return null;
    return payload.u;
  } catch {
    return null;
  }
}

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // Allow login page and static assets
  if (
    pathname === '/login' ||
    pathname === '/login/' ||
    pathname.startsWith('/_next/') ||
    pathname.startsWith('/favicon')
  ) {
    return NextResponse.next();
  }

  const token = request.cookies.get('uip_auth')?.value;
  if (!token) {
    const loginUrl = request.nextUrl.clone();
    loginUrl.pathname = '/login';
    return NextResponse.redirect(loginUrl);
  }

  const username = await verifyToken(token);
  if (!username) {
    const loginUrl = request.nextUrl.clone();
    loginUrl.pathname = '/login';
    const response = NextResponse.redirect(loginUrl);
    response.cookies.delete('uip_auth');
    response.cookies.delete('uip_user');
    return response;
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico|login).*)'],
};
