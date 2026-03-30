'use client';

import { useState, useEffect } from 'react';

interface UserProfile {
  username: string;
  display_name: string;
  jira_email: string;
  has_jira_token: boolean;
  jira_connected: boolean;
  jira_oauth_email: string;
  created_at: string;
}

export default function SettingsPage() {
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [loading, setLoading] = useState(true);

  // Password change
  const [currentPw, setCurrentPw] = useState('');
  const [newPw, setNewPw] = useState('');
  const [confirmPw, setConfirmPw] = useState('');
  const [pwMsg, setPwMsg] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);
  const [pwLoading, setPwLoading] = useState(false);

  // Jira
  const [jiraMsg, setJiraMsg] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);
  const [disconnecting, setDisconnecting] = useState(false);

  useEffect(() => {
    // Check for OAuth callback params from URL
    const params = new URLSearchParams(window.location.search);
    const connected = params.get('jira_connected');
    const jiraError = params.get('jira_error');
    if (connected === 'true') {
      setJiraMsg({ type: 'ok', text: 'Jira account connected successfully!' });
      // Clean URL
      window.history.replaceState({}, '', window.location.pathname);
    } else if (jiraError) {
      const errorMessages: Record<string, string> = {
        'access_denied': 'You denied the Jira authorization request',
        'token_exchange_failed': 'Failed to exchange authorization code — please try again',
        'invalid_state': 'Authorization session expired — please try again',
        'missing_params': 'Missing authorization parameters — please try again',
        'auth_required': 'Please log in first, then connect your Jira account',
      };
      setJiraMsg({ type: 'err', text: errorMessages[jiraError] || `Authorization error: ${jiraError}` });
      window.history.replaceState({}, '', window.location.pathname);
    }

    fetch('/api/auth/me')
      .then((r) => r.json())
      .then((data) => {
        if (data.username) {
          setProfile(data);
        }
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  async function handlePasswordChange(e: React.FormEvent) {
    e.preventDefault();
    setPwMsg(null);
    if (newPw !== confirmPw) {
      setPwMsg({ type: 'err', text: 'New passwords do not match' });
      return;
    }
    if (newPw.length < 8) {
      setPwMsg({ type: 'err', text: 'Password must be at least 8 characters' });
      return;
    }
    setPwLoading(true);
    try {
      const res = await fetch('/api/auth/change-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ current_password: currentPw, new_password: newPw }),
      });
      const data = await res.json();
      if (res.ok && data.ok) {
        setPwMsg({ type: 'ok', text: 'Password changed successfully' });
        setCurrentPw('');
        setNewPw('');
        setConfirmPw('');
      } else {
        setPwMsg({ type: 'err', text: data.error || 'Failed' });
      }
    } catch {
      setPwMsg({ type: 'err', text: 'Network error' });
    } finally {
      setPwLoading(false);
    }
  }

  function handleJiraConnect() {
    // Navigate to the OAuth start endpoint — auth-api will redirect to Atlassian
    window.location.href = '/api/auth/jira/connect';
  }

  async function handleJiraDisconnect() {
    setDisconnecting(true);
    setJiraMsg(null);
    try {
      const res = await fetch('/api/auth/jira/disconnect', { method: 'POST' });
      const data = await res.json();
      if (res.ok && data.ok) {
        setJiraMsg({ type: 'ok', text: 'Jira account disconnected' });
        setProfile((prev) =>
          prev ? { ...prev, jira_connected: false, jira_oauth_email: '', has_jira_token: false } : prev,
        );
      } else {
        setJiraMsg({ type: 'err', text: data.error || 'Failed to disconnect' });
      }
    } catch {
      setJiraMsg({ type: 'err', text: 'Network error' });
    } finally {
      setDisconnecting(false);
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="text-sm text-muted">Loading...</div>
      </div>
    );
  }

  if (!profile) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="text-sm text-red">Failed to load profile</div>
      </div>
    );
  }

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      <div>
        <h1 className="text-xl font-bold text-text-bright">Settings</h1>
        <p className="text-xs text-muted mt-0.5">Manage your account and integrations</p>
      </div>

      {/* Profile Info */}
      <div className="bg-surface border border-border rounded-lg p-5">
        <h2 className="text-sm font-semibold text-text-bright mb-3">Profile</h2>
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-full bg-accent/20 border border-accent/40 flex items-center justify-center text-accent font-bold text-lg uppercase">
            {profile.username[0]}
          </div>
          <div>
            <div className="text-sm font-medium text-text-bright">{profile.username}</div>
            <div className="text-xs text-muted">Member since {profile.created_at?.split('T')[0] || profile.created_at?.split(' ')[0] || 'unknown'}</div>
          </div>
        </div>
      </div>

      {/* Change Password */}
      <div className="bg-surface border border-border rounded-lg p-5">
        <h2 className="text-sm font-semibold text-text-bright mb-3">Change Password</h2>
        {pwMsg && (
          <div
            className={`rounded px-3 py-2 text-xs mb-3 ${
              pwMsg.type === 'ok'
                ? 'bg-green/10 border border-green/30 text-green'
                : 'bg-red/10 border border-red/30 text-red'
            }`}
          >
            {pwMsg.text}
          </div>
        )}
        <form onSubmit={handlePasswordChange} className="space-y-3">
          <div>
            <label className="text-[10px] text-muted block mb-1">Current Password</label>
            <input
              type="password"
              value={currentPw}
              onChange={(e) => setCurrentPw(e.target.value)}
              className="w-full bg-bg border border-border rounded-md px-3 py-2 text-sm text-text-bright focus:outline-none focus:border-accent/50"
              autoComplete="current-password"
              required
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[10px] text-muted block mb-1">New Password</label>
              <input
                type="password"
                value={newPw}
                onChange={(e) => setNewPw(e.target.value)}
                className="w-full bg-bg border border-border rounded-md px-3 py-2 text-sm text-text-bright focus:outline-none focus:border-accent/50"
                autoComplete="new-password"
                minLength={8}
                required
              />
            </div>
            <div>
              <label className="text-[10px] text-muted block mb-1">Confirm New Password</label>
              <input
                type="password"
                value={confirmPw}
                onChange={(e) => setConfirmPw(e.target.value)}
                className="w-full bg-bg border border-border rounded-md px-3 py-2 text-sm text-text-bright focus:outline-none focus:border-accent/50"
                autoComplete="new-password"
                minLength={8}
                required
              />
            </div>
          </div>
          <div className="flex justify-end">
            <button
              type="submit"
              disabled={pwLoading || !currentPw || !newPw || !confirmPw}
              className="px-4 py-1.5 text-xs font-medium rounded-md bg-accent text-white hover:bg-accent-hover disabled:opacity-40 transition-colors"
            >
              {pwLoading ? 'Changing...' : 'Change Password'}
            </button>
          </div>
        </form>
      </div>

      {/* Jira Integration */}
      <div className="bg-surface border border-border rounded-lg p-5">
        <div className="flex items-center justify-between mb-1">
          <h2 className="text-sm font-semibold text-text-bright">Jira Integration</h2>
          {profile.jira_connected ? (
            <span className="text-[10px] px-2 py-0.5 rounded-full bg-green/15 border border-green/30 text-green">
              Connected
            </span>
          ) : (
            <span className="text-[10px] px-2 py-0.5 rounded-full bg-orange/15 border border-orange/30 text-orange">
              Not connected
            </span>
          )}
        </div>
        <p className="text-[11px] text-muted mb-3">
          Connect your Atlassian account so incidents you create are attributed to you.
          No API tokens needed — just click the button and authorize.
        </p>
        {jiraMsg && (
          <div
            className={`rounded px-3 py-2 text-xs mb-3 ${
              jiraMsg.type === 'ok'
                ? 'bg-green/10 border border-green/30 text-green'
                : 'bg-red/10 border border-red/30 text-red'
            }`}
          >
            {jiraMsg.text}
          </div>
        )}

        {profile.jira_connected ? (
          <div className="space-y-3">
            <div className="flex items-center gap-3 p-3 bg-bg rounded-md border border-border">
              <div className="w-8 h-8 rounded-full bg-blue-500/20 border border-blue-500/40 flex items-center justify-center">
                <svg className="w-4 h-4 text-blue-400" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M11.571 11.513H0a5.218 5.218 0 0 0 5.232 5.215h2.13v2.057A5.215 5.215 0 0 0 12.575 24V12.518a1.005 1.005 0 0 0-1.005-1.005zm5.723-5.756H5.736a5.215 5.215 0 0 0 5.215 5.214h2.129v2.058a5.218 5.218 0 0 0 5.215 5.214V6.758a1.001 1.001 0 0 0-1.001-1.001zM23.013 0H11.455a5.215 5.215 0 0 0 5.215 5.215h2.129v2.057A5.215 5.215 0 0 0 24.013 12.487V1.005A1.005 1.005 0 0 0 23.013 0z"/>
                </svg>
              </div>
              <div className="flex-1">
                <div className="text-sm text-text-bright font-medium">
                  {profile.jira_oauth_email || 'Atlassian Account'}
                </div>
                <div className="text-[10px] text-muted">Jira account linked — tickets will be created under your identity</div>
              </div>
            </div>
            <div className="flex justify-end gap-2">
              <button
                onClick={handleJiraConnect}
                className="px-3 py-1.5 text-xs font-medium rounded-md bg-surface border border-border text-muted hover:text-text-bright hover:border-accent/50 transition-colors"
              >
                Reconnect
              </button>
              <button
                onClick={handleJiraDisconnect}
                disabled={disconnecting}
                className="px-3 py-1.5 text-xs font-medium rounded-md bg-red/10 border border-red/30 text-red hover:bg-red/20 disabled:opacity-40 transition-colors"
              >
                {disconnecting ? 'Disconnecting...' : 'Disconnect'}
              </button>
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            <button
              onClick={handleJiraConnect}
              className="w-full flex items-center justify-center gap-2 px-4 py-2.5 text-sm font-medium rounded-md bg-[#0052CC] text-white hover:bg-[#0065FF] transition-colors"
            >
              <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                <path d="M11.571 11.513H0a5.218 5.218 0 0 0 5.232 5.215h2.13v2.057A5.215 5.215 0 0 0 12.575 24V12.518a1.005 1.005 0 0 0-1.005-1.005zm5.723-5.756H5.736a5.215 5.215 0 0 0 5.215 5.214h2.129v2.058a5.218 5.218 0 0 0 5.215 5.214V6.758a1.001 1.001 0 0 0-1.001-1.001zM23.013 0H11.455a5.215 5.215 0 0 0 5.215 5.215h2.129v2.057A5.215 5.215 0 0 0 24.013 12.487V1.005A1.005 1.005 0 0 0 23.013 0z"/>
              </svg>
              Connect Jira Account
            </button>
            <p className="text-[10px] text-muted text-center">
              You&apos;ll be redirected to Atlassian to authorize access. UIP will only be able to create and read Jira issues.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
