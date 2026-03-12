'use client';

import { useState } from 'react';

export default function LoginPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username.trim().toLowerCase(), password }),
      });
      const data = await res.json();
      if (res.ok && data.ok) {
        window.location.href = '/portal/command-center';
      } else {
        setError(data.error || 'Login failed');
      }
    } catch {
      setError('Network error');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="fixed inset-0 z-[100] bg-bg flex items-center justify-center">
      <div className="w-full max-w-sm px-4">
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-accent tracking-tight">UIP</h1>
          <p className="text-sm text-muted mt-1">SRE Command Center</p>
        </div>
        <form onSubmit={handleSubmit} className="bg-surface border border-border rounded-lg p-6 space-y-4">
          <h2 className="text-lg font-semibold text-text-bright">Sign In</h2>

          {error && (
            <div className="bg-red/10 border border-red/30 rounded px-3 py-2 text-xs text-red">{error}</div>
          )}

          <div>
            <label className="text-xs text-muted block mb-1">Username</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full bg-bg border border-border rounded-md px-3 py-2 text-sm text-text-bright font-mono placeholder:text-muted/50 focus:outline-none focus:border-accent/50"
              placeholder="e.g. fash"
              autoFocus
              autoComplete="username"
              required
            />
          </div>

          <div>
            <label className="text-xs text-muted block mb-1">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full bg-bg border border-border rounded-md px-3 py-2 text-sm text-text-bright placeholder:text-muted/50 focus:outline-none focus:border-accent/50"
              autoComplete="current-password"
              required
            />
          </div>

          <button
            type="submit"
            disabled={loading || !username || !password}
            className="w-full bg-accent hover:bg-accent-hover text-white font-medium py-2.5 rounded-md transition-colors disabled:opacity-40"
          >
            {loading ? 'Signing in...' : 'Sign In'}
          </button>

          <p className="text-[10px] text-muted/50 text-center">Tucows Domains SRE</p>
        </form>
      </div>
    </div>
  );
}
