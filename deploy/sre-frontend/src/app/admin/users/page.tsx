'use client';

import { useState, useEffect, useCallback } from 'react';
import { Role, SharedMaintenanceAuthConfig, UserProfile } from '@/lib/types';
import {
  fetchUsers, createUser, updateUser, deleteUser,
  fetchRoles, createRole, updateRole, deleteRole, updateRolePermissions,
  fetchSharedMaintenanceAuth, saveSharedMaintenanceAuth, testSharedMaintenanceAuth, clearSharedMaintenanceAuth,
  ALL_PERMISSIONS,
} from '@/lib/keep-api';
import { useAuth } from '@/lib/auth';

export default function AdminPage() {
  const { hasPermission, loading: authLoading } = useAuth();
  const [tab, setTab] = useState<'users' | 'roles'>('users');

  // ── Users state ──
  const [users, setUsers] = useState<UserProfile[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [loadingData, setLoadingData] = useState(true);
  const [msg, setMsg] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);

  // Add user form
  const [showAddUser, setShowAddUser] = useState(false);
  const [newUsername, setNewUsername] = useState('');
  const [newDisplayName, setNewDisplayName] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newRoleId, setNewRoleId] = useState(2);
  const [saving, setSaving] = useState(false);

  // Edit user
  const [editUserId, setEditUserId] = useState<number | null>(null);
  const [editRoleId, setEditRoleId] = useState(2);
  const [editDisplayName, setEditDisplayName] = useState('');
  const [editPassword, setEditPassword] = useState('');

  // Add role form
  const [showAddRole, setShowAddRole] = useState(false);
  const [newRoleName, setNewRoleName] = useState('');
  const [newRoleDesc, setNewRoleDesc] = useState('');
  const [newRolePerms, setNewRolePerms] = useState<string[]>([]);

  // Edit role permissions
  const [editRolePermId, setEditRolePermId] = useState<number | null>(null);
  const [editPerms, setEditPerms] = useState<string[]>([]);
  const [sharedMaint, setSharedMaint] = useState<SharedMaintenanceAuthConfig | null>(null);
  const [sharedMaintUser, setSharedMaintUser] = useState('');
  const [sharedMaintPassword, setSharedMaintPassword] = useState('');
  const [sharedMaintSaving, setSharedMaintSaving] = useState(false);
  const [sharedMaintTesting, setSharedMaintTesting] = useState(false);
  const [sharedMaintClearing, setSharedMaintClearing] = useState(false);

  const loadData = useCallback(async () => {
    setLoadingData(true);
    try {
      const [u, r, maintenance] = await Promise.all([fetchUsers(), fetchRoles(), fetchSharedMaintenanceAuth()]);
      setUsers(u);
      setRoles(r);
      setSharedMaint(maintenance);
      setSharedMaintUser(maintenance.username || '');
    } catch (e: unknown) {
      setMsg({ type: 'err', text: e instanceof Error ? e.message : 'Failed to load admin data' });
    } finally {
      setLoadingData(false);
    }
  }, []);

  useEffect(() => {
    if (!authLoading && hasPermission('view_admin')) {
      loadData();
    }
  }, [authLoading, hasPermission, loadData]);

  if (authLoading) return <div className="p-8 text-muted">Loading...</div>;
  if (!hasPermission('view_admin')) {
    return <div className="p-8 text-red-400">Access denied. Admin permission required.</div>;
  }

  const handleAddUser = async () => {
    if (!newUsername || !newPassword) return;
    setSaving(true);
    const res = await createUser(newUsername, newDisplayName || newUsername, newPassword, newRoleId);
    setSaving(false);
    if (res.ok) {
      setMsg({ type: 'ok', text: `User '${newUsername}' created` });
      setShowAddUser(false);
      setNewUsername(''); setNewDisplayName(''); setNewPassword(''); setNewRoleId(2);
      loadData();
    } else {
      setMsg({ type: 'err', text: res.error || 'Failed to create user' });
    }
  };

  const handleUpdateUser = async (id: number) => {
    setSaving(true);
    const data: any = {};
    if (editDisplayName) data.display_name = editDisplayName;
    if (editRoleId) data.role_id = editRoleId;
    if (editPassword) data.password = editPassword;
    const res = await updateUser(id, data);
    setSaving(false);
    if (res.ok) {
      setMsg({ type: 'ok', text: 'User updated' });
      setEditUserId(null);
      loadData();
    } else {
      setMsg({ type: 'err', text: res.error || 'Failed to update user' });
    }
  };

  const handleDeleteUser = async (id: number, username: string) => {
    if (!confirm(`Delete user '${username}'? This cannot be undone.`)) return;
    const res = await deleteUser(id);
    if (res.ok) {
      setMsg({ type: 'ok', text: `User '${username}' deleted` });
      loadData();
    } else {
      setMsg({ type: 'err', text: res.error || 'Failed to delete user' });
    }
  };

  const handleAddRole = async () => {
    if (!newRoleName) return;
    setSaving(true);
    const res = await createRole(newRoleName, newRoleDesc, newRolePerms);
    setSaving(false);
    if (res.ok) {
      setMsg({ type: 'ok', text: `Role '${newRoleName}' created` });
      setShowAddRole(false);
      setNewRoleName(''); setNewRoleDesc(''); setNewRolePerms([]);
      loadData();
    } else {
      setMsg({ type: 'err', text: res.error || 'Failed to create role' });
    }
  };

  const handleDeleteRole = async (id: number, name: string) => {
    if (!confirm(`Delete role '${name}'?`)) return;
    const res = await deleteRole(id);
    if (res.ok) {
      setMsg({ type: 'ok', text: `Role '${name}' deleted` });
      loadData();
    } else {
      setMsg({ type: 'err', text: res.error || 'Failed to delete role' });
    }
  };

  const handleSavePermissions = async (roleId: number) => {
    setSaving(true);
    const res = await updateRolePermissions(roleId, editPerms);
    setSaving(false);
    if (res.ok) {
      setMsg({ type: 'ok', text: 'Permissions updated' });
      setEditRolePermId(null);
      loadData();
    } else {
      setMsg({ type: 'err', text: res.error || 'Failed to update permissions' });
    }
  };

  const handleSaveSharedMaintenance = async () => {
    if (!sharedMaintUser.trim() || !sharedMaintPassword) return;
    setSharedMaintSaving(true);
    const res = await saveSharedMaintenanceAuth(sharedMaintUser.trim(), sharedMaintPassword);
    setSharedMaintSaving(false);
    if (res.ok) {
      setMsg({ type: 'ok', text: 'Shared maintenance auth saved' });
      setSharedMaintPassword('');
      loadData();
    } else {
      setMsg({ type: 'err', text: res.error || 'Failed to save shared maintenance auth' });
    }
  };

  const handleTestSharedMaintenance = async () => {
    setSharedMaintTesting(true);
    const res = await testSharedMaintenanceAuth();
    setSharedMaintTesting(false);
    if (res.ok) {
      setMsg({ type: 'ok', text: 'Shared maintenance auth test succeeded' });
    } else {
      setMsg({ type: 'err', text: res.error || 'Failed to test shared maintenance auth' });
    }
  };

  const handleClearSharedMaintenance = async () => {
    if (!confirm('Clear the shared maintenance credential?')) return;
    setSharedMaintClearing(true);
    const res = await clearSharedMaintenanceAuth();
    setSharedMaintClearing(false);
    if (res.ok) {
      setSharedMaintPassword('');
      setMsg({ type: 'ok', text: 'Shared maintenance auth cleared' });
      loadData();
    } else {
      setMsg({ type: 'err', text: res.error || 'Failed to clear shared maintenance auth' });
    }
  };

  const togglePerm = (perm: string, permList: string[], setter: (p: string[]) => void) => {
    setter(permList.includes(perm) ? permList.filter(p => p !== perm) : [...permList, perm]);
  };

  const permGroups = ALL_PERMISSIONS.reduce((acc, p) => {
    if (!acc[p.group]) acc[p.group] = [];
    acc[p.group].push(p);
    return acc;
  }, {} as Record<string, typeof ALL_PERMISSIONS>);

  const PermissionChecklist = ({ perms, onChange }: { perms: string[]; onChange: (p: string[]) => void }) => (
    <div className="space-y-3">
      {Object.entries(permGroups).map(([group, items]) => (
        <div key={group}>
          <h5 className="text-xs font-medium text-muted uppercase tracking-wide mb-1">{group}</h5>
          <div className="grid grid-cols-2 gap-1">
            {items.map(p => (
              <label key={p.key} className="flex items-center gap-2 text-xs text-text cursor-pointer hover:text-text-bright">
                <input
                  type="checkbox"
                  checked={perms.includes(p.key)}
                  onChange={() => togglePerm(p.key, perms, onChange)}
                  className="rounded border-border"
                />
                {p.label}
              </label>
            ))}
          </div>
        </div>
      ))}
    </div>
  );

  return (
    <div className="max-w-5xl mx-auto p-6 space-y-6">
      <h1 className="text-xl font-bold text-text-bright">Admin</h1>

      {msg && (
        <div className={`p-3 rounded text-sm ${msg.type === 'ok' ? 'bg-green-900/30 text-green-400 border border-green-800' : 'bg-red-900/30 text-red-400 border border-red-800'}`}>
          {msg.text}
          <button onClick={() => setMsg(null)} className="float-right text-xs opacity-60 hover:opacity-100">dismiss</button>
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-1 border-b border-border">
        {(['users', 'roles'] as const).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${tab === t ? 'border-accent text-accent' : 'border-transparent text-muted hover:text-text'}`}
          >
            {t === 'users' ? 'Users' : 'Roles'}
          </button>
        ))}
      </div>

      {loadingData ? (
        <div className="text-center py-8 text-muted">Loading...</div>
      ) : tab === 'users' ? (
        <div className="space-y-4">
          <div className="flex justify-between items-center">
            <h2 className="text-sm font-medium text-text-bright">{users.length} Users</h2>
            {hasPermission('manage_users') && (
              <button
                onClick={() => setShowAddUser(!showAddUser)}
                className="px-3 py-1.5 text-xs font-medium bg-accent text-white rounded hover:bg-accent/80"
              >
                {showAddUser ? 'Cancel' : '+ Add User'}
              </button>
            )}
          </div>

          {showAddUser && (
            <div className="p-4 bg-surface border border-border rounded-lg space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <input
                  placeholder="Username"
                  value={newUsername}
                  onChange={e => setNewUsername(e.target.value)}
                  className="px-3 py-2 text-sm bg-background border border-border rounded text-text"
                />
                <input
                  placeholder="Display Name"
                  value={newDisplayName}
                  onChange={e => setNewDisplayName(e.target.value)}
                  className="px-3 py-2 text-sm bg-background border border-border rounded text-text"
                />
                <input
                  type="password"
                  placeholder="Password (min 8 chars)"
                  value={newPassword}
                  onChange={e => setNewPassword(e.target.value)}
                  className="px-3 py-2 text-sm bg-background border border-border rounded text-text"
                />
                <select
                  value={newRoleId}
                  onChange={e => setNewRoleId(Number(e.target.value))}
                  className="px-3 py-2 text-sm bg-background border border-border rounded text-text"
                >
                  {roles.map(r => <option key={r.id} value={r.id}>{r.name}</option>)}
                </select>
              </div>
              <button
                onClick={handleAddUser}
                disabled={saving || !newUsername || !newPassword}
                className="px-4 py-2 text-xs font-medium bg-accent text-white rounded hover:bg-accent/80 disabled:opacity-50"
              >
                {saving ? 'Creating...' : 'Create User'}
              </button>
            </div>
          )}

          <div className="bg-surface border border-border rounded-lg overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-left text-xs text-muted uppercase">
                  <th className="px-4 py-2">Username</th>
                  <th className="px-4 py-2">Display Name</th>
                  <th className="px-4 py-2">Role</th>
                  <th className="px-4 py-2">Created</th>
                  <th className="px-4 py-2">Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map(u => (
                  <tr key={u.id || u.username} className="border-b border-border/50 hover:bg-surface-hover">
                    <td className="px-4 py-2 text-text-bright font-medium">{u.username}</td>
                    <td className="px-4 py-2 text-text">
                      {editUserId === u.id ? (
                        <input
                          value={editDisplayName}
                          onChange={e => setEditDisplayName(e.target.value)}
                          className="px-2 py-1 text-xs bg-background border border-border rounded text-text w-full"
                        />
                      ) : u.display_name}
                    </td>
                    <td className="px-4 py-2">
                      {editUserId === u.id ? (
                        <select
                          value={editRoleId}
                          onChange={e => setEditRoleId(Number(e.target.value))}
                          className="px-2 py-1 text-xs bg-background border border-border rounded text-text"
                        >
                          {roles.map(r => <option key={r.id} value={r.id}>{r.name}</option>)}
                        </select>
                      ) : (
                        <span className={`px-2 py-0.5 rounded-full text-xs ${
                          u.role_name === 'Admin' ? 'bg-red-900/30 text-red-400' :
                          u.role_name === 'SRE' ? 'bg-blue-900/30 text-blue-400' :
                          'bg-gray-900/30 text-gray-400'
                        }`}>
                          {u.role_name || 'SRE'}
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-2 text-xs text-muted">{u.created_at ? new Date(u.created_at).toLocaleDateString() : ''}</td>
                    <td className="px-4 py-2">
                      {hasPermission('manage_users') && (
                        editUserId === u.id ? (
                          <div className="flex gap-2">
                            <input
                              type="password"
                              placeholder="New password (optional)"
                              value={editPassword}
                              onChange={e => setEditPassword(e.target.value)}
                              className="px-2 py-1 text-xs bg-background border border-border rounded text-text w-32"
                            />
                            <button
                              onClick={() => handleUpdateUser(u.id!)}
                              disabled={saving}
                              className="text-xs text-green-400 hover:text-green-300"
                            >
                              Save
                            </button>
                            <button
                              onClick={() => setEditUserId(null)}
                              className="text-xs text-muted hover:text-text"
                            >
                              Cancel
                            </button>
                          </div>
                        ) : (
                          <div className="flex gap-2">
                            <button
                              onClick={() => {
                                setEditUserId(u.id!);
                                setEditDisplayName(u.display_name || '');
                                setEditRoleId(u.role_id || 2);
                                setEditPassword('');
                              }}
                              className="text-xs text-accent hover:text-accent/80"
                            >
                              Edit
                            </button>
                            <button
                              onClick={() => handleDeleteUser(u.id!, u.username)}
                              className="text-xs text-red-400 hover:text-red-300"
                            >
                              Delete
                            </button>
                          </div>
                        )
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        /* ── Roles Tab ── */
        <div className="space-y-4">
          <div className="flex justify-between items-center">
            <h2 className="text-sm font-medium text-text-bright">{roles.length} Roles</h2>
            {hasPermission('manage_roles') && (
              <button
                onClick={() => setShowAddRole(!showAddRole)}
                className="px-3 py-1.5 text-xs font-medium bg-accent text-white rounded hover:bg-accent/80"
              >
                {showAddRole ? 'Cancel' : '+ Add Role'}
              </button>
            )}
          </div>

          {showAddRole && (
            <div className="p-4 bg-surface border border-border rounded-lg space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <input
                  placeholder="Role Name"
                  value={newRoleName}
                  onChange={e => setNewRoleName(e.target.value)}
                  className="px-3 py-2 text-sm bg-background border border-border rounded text-text"
                />
                <input
                  placeholder="Description"
                  value={newRoleDesc}
                  onChange={e => setNewRoleDesc(e.target.value)}
                  className="px-3 py-2 text-sm bg-background border border-border rounded text-text"
                />
              </div>
              <PermissionChecklist perms={newRolePerms} onChange={setNewRolePerms} />
              <button
                onClick={handleAddRole}
                disabled={saving || !newRoleName}
                className="px-4 py-2 text-xs font-medium bg-accent text-white rounded hover:bg-accent/80 disabled:opacity-50"
              >
                {saving ? 'Creating...' : 'Create Role'}
              </button>
            </div>
          )}

          <div className="bg-surface border border-border rounded-lg p-4 space-y-3">
            <div className="flex items-center justify-between gap-4">
              <div>
                <h3 className="text-sm font-medium text-text-bright">Shared Maintenance Auth</h3>
                <p className="text-xs text-muted mt-1">
                  Admin and SRE users auto-connect to maintenance webhook actions using this shared credential.
                </p>
              </div>
              <span className={`text-xs font-medium ${sharedMaint?.configured ? 'text-green-400' : 'text-yellow-400'}`}>
                {sharedMaint?.configured ? 'Configured' : 'Not Configured'}
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <input
                value={sharedMaintUser}
                onChange={(e) => setSharedMaintUser(e.target.value)}
                className="px-3 py-2 text-sm bg-background border border-border rounded text-text"
                placeholder="Maintenance username"
              />
              <input
                type="password"
                value={sharedMaintPassword}
                onChange={(e) => setSharedMaintPassword(e.target.value)}
                className="px-3 py-2 text-sm bg-background border border-border rounded text-text"
                placeholder="Enter new maintenance password"
              />
            </div>

            <div className="flex flex-wrap items-center gap-2 text-xs text-muted">
              <span>Updated by: {sharedMaint?.updated_by || 'n/a'}</span>
              <span>Updated at: {sharedMaint?.updated_at ? new Date(sharedMaint.updated_at).toLocaleString() : 'n/a'}</span>
            </div>

            <div className="flex flex-wrap gap-2">
              <button
                onClick={handleSaveSharedMaintenance}
                disabled={sharedMaintSaving || !sharedMaintUser.trim() || !sharedMaintPassword}
                className="px-3 py-1.5 text-xs font-medium bg-accent text-white rounded hover:bg-accent/80 disabled:opacity-50"
              >
                {sharedMaintSaving ? 'Saving...' : 'Save'}
              </button>
              <button
                onClick={handleTestSharedMaintenance}
                disabled={sharedMaintTesting || !sharedMaint?.configured}
                className="px-3 py-1.5 text-xs font-medium border border-border rounded text-text hover:bg-surface-hover disabled:opacity-50"
              >
                {sharedMaintTesting ? 'Testing...' : 'Test'}
              </button>
              <button
                onClick={handleClearSharedMaintenance}
                disabled={sharedMaintClearing || !sharedMaint?.configured}
                className="px-3 py-1.5 text-xs font-medium border border-red-800 rounded text-red-400 hover:bg-red-900/20 disabled:opacity-50"
              >
                {sharedMaintClearing ? 'Clearing...' : 'Clear'}
              </button>
            </div>
          </div>

          <div className="space-y-3">
            {roles.map(role => (
              <div key={role.id} className="bg-surface border border-border rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <h3 className="text-sm font-medium text-text-bright">{role.name}</h3>
                    {role.is_system && (
                      <span className="px-1.5 py-0.5 text-[10px] bg-yellow-900/30 text-yellow-400 rounded">System</span>
                    )}
                    <span className="text-xs text-muted">{role.user_count || 0} users</span>
                  </div>
                  <div className="flex gap-2">
                    {hasPermission('manage_roles') && (
                      <>
                        <button
                          onClick={() => {
                            if (editRolePermId === role.id) {
                              setEditRolePermId(null);
                            } else {
                              setEditRolePermId(role.id);
                              setEditPerms([...role.permissions]);
                            }
                          }}
                          className="text-xs text-accent hover:text-accent/80"
                        >
                          {editRolePermId === role.id ? 'Cancel' : 'Edit Permissions'}
                        </button>
                        {!role.is_system && (
                          <button
                            onClick={() => handleDeleteRole(role.id, role.name)}
                            disabled={(role.user_count || 0) > 0}
                            className="text-xs text-red-400 hover:text-red-300 disabled:opacity-30 disabled:cursor-not-allowed"
                            title={(role.user_count || 0) > 0 ? `Reassign ${role.user_count} user(s) before deleting` : ''}
                          >
                            Delete
                          </button>
                        )}
                      </>
                    )}
                  </div>
                </div>
                <p className="text-xs text-muted mb-2">{role.description}</p>
                {editRolePermId === role.id ? (
                  <div className="space-y-3 pt-2 border-t border-border">
                    <PermissionChecklist perms={editPerms} onChange={setEditPerms} />
                    <button
                      onClick={() => handleSavePermissions(role.id)}
                      disabled={saving}
                      className="px-3 py-1.5 text-xs font-medium bg-accent text-white rounded hover:bg-accent/80 disabled:opacity-50"
                    >
                      {saving ? 'Saving...' : 'Save Permissions'}
                    </button>
                  </div>
                ) : (
                  <div className="flex flex-wrap gap-1">
                    {role.permissions.map(p => (
                      <span key={p} className="px-1.5 py-0.5 text-[10px] bg-background text-muted rounded border border-border">
                        {p}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
