/** Read a cookie value from document.cookie */
export function getCookie(name: string): string | null {
  if (typeof document === 'undefined') return null;
  const match = document.cookie.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

/** Get the authenticated username from the uip_user cookie */
export function getClientUsername(): string | null {
  return getCookie('uip_user') || null;
}
