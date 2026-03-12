'use client';

import { useState, useEffect } from 'react';

interface UserProfile {
  username: string;
  display_name: string;
  jira_email: string;
  has_jira_token: boolean;
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

  // Jira config
  const [jiraEmail, setJiraEmail] = useState('');
  const [jiraToken, setJiraToken] = useState('');
  const [jiraMsg, setJiraMsg] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);
  const [jiraLoading, setJiraLoading] = useState(false);

  useEffect(() => {
    fetch('/api/auth/me')
      .then((r) => r.json())
      .then((data) => {
        if (data.username) {
          setProfile(data);
          setJiraEmail(data.jira_email || '');
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

  async function handleJiraConfig(e: React.FormEvent) {
    e.preventDefault();
    setJiraMsg(null);
    setJiraLoading(true);
    try {
      const res = await fetch('/api/auth/jira-config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jira_email: jiraEmail, jira_api_token: jiraToken }),
      });
      const data = await res.json();
      if (res.ok && data.ok) {
        setJiraMsg({ type: 'ok', text: 'Jira configuration saved' });
        setJiraToken('');
        setProfile((prev) =>
          prev ? { ...prev, jira_email: jiraEmail, has_jira_token: data.has_jira_token } : prev,
        );
      } else {
        setJiraMsg({ type: 'err', text: data.error || 'Failed' });
      }
    } catch {
      setJiraMsg({ type: 'err', text: 'Network error' });
    } finally {
      setJiraLoading(false);
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
          {profile.has_jira_token ? (
            <span className="text-[10px] px-2 py-0.5 rounded-full bg-green/15 border border-green/30 text-green">
              Configured
            </span>
          ) : (
            <span className="text-[10px] px-2 py-0.5 rounded-full bg-orange/15 border border-orange/30 text-orange">
              Not configured
            </span>
          )}
        </div>
        <p className="text-[11px] text-muted mb-3">
          Connect your Jira account so incidents you create are attributed to you.
          Generate an API token at{' '}
          <a
            href="https://id.atlassian.com/manage-profile/security/api-tokens"
            target="_blank"
            rel="noopener noreferrer"
            className="text-accent hover:underline"
          >
            id.atlassian.com
          </a>
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
        <form onSubmit={handleJiraConfig} className="space-y-3">
          <div>
            <label className="text-[10px] text-muted block mb-1">Jira Email</label>
            <input
              type="email"
              value={jiraEmail}
              onChange={(e) => setJiraEmail(e.target.value)}
              placeholder="you@tucows.com"
              className="w-full bg-bg border border-border rounded-md px-3 py-2 text-sm text-text-bright font-mono placeholder:text-muted/50 focus:outline-none focus:border-accent/50"
            />
          </div>
          <div>
            <label className="text-[10px] text-muted block mb-1">
              API Token {profile.has_jira_token && <span className="text-muted/50">(leave blank to keep existing)</span>}
            </label>
            <input
              type="password"
              value={jiraToken}
              onChange={(e) => setJiraToken(e.target.value)}
              placeholder={profile.has_jira_token ? '••••••••••••' : 'Paste your Jira API token'}
              className="w-full bg-bg border border-border rounded-md px-3 py-2 text-sm text-text-bright font-mono placeholder:text-muted/50 focus:outline-none focus:border-accent/50"
            />
          </div>
          <div className="flex justify-end">
            <button
              type="submit"
              disabled={jiraLoading || !jiraEmail}
              className="px-4 py-1.5 text-xs font-medium rounded-md bg-accent text-white hover:bg-accent-hover disabled:opacity-40 transition-colors"
            >
              {jiraLoading ? 'Saving...' : 'Save Jira Config'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
