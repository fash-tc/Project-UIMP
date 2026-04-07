'use client';

import { useState, useEffect, useCallback } from 'react';
import {
  fetchAlertRules, createAlertRule, updateAlertRule, deleteAlertRule,
  AlertRule, CONDITION_FIELDS, CONDITION_OPERATORS, normalizeHighlightColor, colorWithAlpha,
} from '@/lib/keep-api';
import { useAuth } from '@/lib/auth';

interface ConditionRow {
  field: string;
  op: string;
  value: string;
}

function conditionRowsToJson(rows: ConditionRow[], logic: 'AND' | 'OR'): any {
  const leaves = rows.map(r => ({ field: r.field, op: r.op, value: r.value }));
  if (leaves.length === 1) return leaves[0];
  return { [logic]: leaves };
}

function conditionJsonToRows(cond: any): { rows: ConditionRow[]; logic: 'AND' | 'OR' } {
  if (!cond) return { rows: [{ field: 'hostname', op: 'contains', value: '' }], logic: 'AND' };
  if (cond.AND) return { rows: cond.AND.map((c: any) => ({ field: c.field || '', op: c.op || 'contains', value: c.value || '' })), logic: 'AND' };
  if (cond.OR) return { rows: cond.OR.map((c: any) => ({ field: c.field || '', op: c.op || 'contains', value: c.value || '' })), logic: 'OR' };
  if (cond.field) return { rows: [{ field: cond.field, op: cond.op || 'contains', value: cond.value || '' }], logic: 'AND' };
  return { rows: [{ field: 'hostname', op: 'contains', value: '' }], logic: 'AND' };
}

function generateExpression(rows: ConditionRow[], logic: string): string {
  return rows.map(r => {
    const fieldLabel = CONDITION_FIELDS.find(f => f.value === r.field)?.label || r.field;
    const opLabel = CONDITION_OPERATORS.find(o => o.value === r.op)?.label || r.op;
    return `${fieldLabel} ${opLabel} "${r.value}"`;
  }).join(` ${logic} `);
}

export function AlertRulesManager({ embedded = false }: { embedded?: boolean }) {
  const { hasPermission, loading: authLoading } = useAuth();
  const [tab, setTab] = useState<'routing' | 'highlight'>('routing');
  const [rules, setRules] = useState<AlertRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [msg, setMsg] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);

  // Form state
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [formName, setFormName] = useState('');
  const [formRows, setFormRows] = useState<ConditionRow[]>([{ field: 'hostname', op: 'contains', value: '' }]);
  const [formLogic, setFormLogic] = useState<'AND' | 'OR'>('AND');
  const [formAction, setFormAction] = useState('auto_ack');
  const [formActionParams, setFormActionParams] = useState<any>({});
  const [formColor, setFormColor] = useState('#ef4444');
  const [formHighlightStyle, setFormHighlightStyle] = useState<'side' | 'box'>('side');
  const [formLabel, setFormLabel] = useState('');
  const [formPriority, setFormPriority] = useState(100);
  const [formEnabled, setFormEnabled] = useState(true);
  const [showRawExpr, setShowRawExpr] = useState(false);
  const [saving, setSaving] = useState(false);

  const loadRules = useCallback(async () => {
    setLoading(true);
    const data = await fetchAlertRules(tab);
    setRules(data);
    setLoading(false);
  }, [tab]);

  useEffect(() => { loadRules(); }, [loadRules]);

  if (authLoading) return <div className="p-8 text-muted">Loading...</div>;

  const resetForm = () => {
    setFormName('');
    setFormRows([{ field: 'hostname', op: 'contains', value: '' }]);
    setFormLogic('AND');
    setFormAction('auto_ack');
    setFormActionParams({});
    setFormColor('#ef4444');
    setFormHighlightStyle('side');
    setFormLabel('');
    setFormPriority(100);
    setFormEnabled(true);
    setEditingId(null);
    setShowRawExpr(false);
  };

  const openEditForm = (rule: AlertRule) => {
    setEditingId(rule.id);
    setFormName(rule.name);
    const { rows, logic } = conditionJsonToRows(rule.conditions_json);
    setFormRows(rows);
    setFormLogic(logic);
    setFormAction(rule.action || 'auto_ack');
    setFormActionParams(rule.action_params || {});
    setFormColor(normalizeHighlightColor(rule.color));
    setFormHighlightStyle(rule.action_params?.highlight_style === 'box' ? 'box' : 'side');
    setFormLabel(rule.label || '');
    setFormPriority(rule.priority);
    setFormEnabled(rule.enabled);
    setShowForm(true);
  };

  const handleSave = async () => {
    if (!formName) return;
    setSaving(true);
    const conditions = conditionRowsToJson(formRows, formLogic);
    const expression = generateExpression(formRows, formLogic);
    const payload: Partial<AlertRule> = {
      name: formName,
      rule_type: tab,
      conditions_json: conditions,
      expression_text: expression,
      priority: formPriority,
      enabled: formEnabled,
    };
    if (tab === 'routing') {
      payload.action = formAction;
      payload.action_params = formActionParams;
    } else {
      payload.color = normalizeHighlightColor(formColor);
      payload.label = formLabel;
      payload.action_params = { highlight_style: formHighlightStyle };
    }
    let res;
    if (editingId) {
      res = await updateAlertRule(editingId, payload);
    } else {
      res = await createAlertRule(payload);
    }
    setSaving(false);
    if (res.ok) {
      setMsg({ type: 'ok', text: editingId ? 'Rule updated' : 'Rule created' });
      setShowForm(false);
      resetForm();
      loadRules();
    } else {
      setMsg({ type: 'err', text: res.error || 'Failed' });
    }
  };

  const handleDelete = async (id: number, name: string) => {
    if (!confirm(`Delete rule '${name}'?`)) return;
    const res = await deleteAlertRule(id);
    if (res.ok) {
      setMsg({ type: 'ok', text: `Rule '${name}' deleted` });
      loadRules();
    } else {
      setMsg({ type: 'err', text: res.error || 'Failed' });
    }
  };

  const handleToggle = async (rule: AlertRule) => {
    const res = await updateAlertRule(rule.id, { enabled: !rule.enabled });
    if (res.ok) loadRules();
  };

  const updateRow = (idx: number, field: keyof ConditionRow, value: string) => {
    const updated = [...formRows];
    updated[idx] = { ...updated[idx], [field]: value };
    setFormRows(updated);
  };

  const containerClass = embedded ? 'space-y-6' : 'max-w-5xl mx-auto p-6 space-y-6';
  const previewColor = normalizeHighlightColor(formColor);

  return (
    <div className={containerClass}>
      {!embedded && <h1 className="text-xl font-bold text-text-bright">Alert Rules</h1>}

      {msg && (
        <div className={`p-3 rounded text-sm ${msg.type === 'ok' ? 'bg-green-900/30 text-green-400 border border-green-800' : 'bg-red-900/30 text-red-400 border border-red-800'}`}>
          {msg.text}
          <button onClick={() => setMsg(null)} className="float-right text-xs opacity-60 hover:opacity-100">dismiss</button>
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-1 border-b border-border">
        {(['routing', 'highlight'] as const).map(t => (
          <button
            key={t}
            onClick={() => { setTab(t); setShowForm(false); resetForm(); }}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${tab === t ? 'border-accent text-accent' : 'border-transparent text-muted hover:text-text'}`}
          >
            {t === 'routing' ? 'Routing Rules' : 'Highlighting Rules'}
          </button>
        ))}
      </div>

      <div className="flex justify-between items-center">
        <h2 className="text-sm font-medium text-text-bright">{rules.length} {tab} rules</h2>
        <button
          onClick={() => { if (showForm) { setShowForm(false); resetForm(); } else { setShowForm(true); } }}
          className="px-3 py-1.5 text-xs font-medium bg-accent text-white rounded hover:bg-accent/80"
        >
          {showForm ? 'Cancel' : '+ Add Rule'}
        </button>
      </div>

      {/* Form */}
      {showForm && (
        <div className="p-4 bg-surface border border-border rounded-lg space-y-4">
          <div className="grid grid-cols-3 gap-3">
            <input
              placeholder="Rule name"
              value={formName}
              onChange={e => setFormName(e.target.value)}
              className="px-3 py-2 text-sm bg-background border border-border rounded text-text"
            />
            <input
              type="number"
              placeholder="Priority"
              value={formPriority}
              onChange={e => setFormPriority(Number(e.target.value))}
              className="px-3 py-2 text-sm bg-background border border-border rounded text-text"
            />
            <label className="flex items-center gap-2 text-sm text-text">
              <input type="checkbox" checked={formEnabled} onChange={e => setFormEnabled(e.target.checked)} />
              Enabled
            </label>
          </div>

          {/* Condition Builder */}
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-xs text-muted">
              <span>Conditions:</span>
              <button
                onClick={() => setFormLogic(formLogic === 'AND' ? 'OR' : 'AND')}
                className="px-2 py-0.5 bg-accent/20 text-accent rounded text-xs font-medium"
              >
                {formLogic}
              </button>
            </div>
            {formRows.map((row, idx) => (
              <div key={idx} className="flex gap-2 items-center">
                <select value={row.field} onChange={e => updateRow(idx, 'field', e.target.value)}
                  className="px-2 py-1.5 text-xs bg-background border border-border rounded text-text">
                  {CONDITION_FIELDS.map(f => <option key={f.value} value={f.value}>{f.label}</option>)}
                </select>
                <select value={row.op} onChange={e => updateRow(idx, 'op', e.target.value)}
                  className="px-2 py-1.5 text-xs bg-background border border-border rounded text-text">
                  {CONDITION_OPERATORS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                </select>
                <input
                  value={row.value}
                  onChange={e => updateRow(idx, 'value', e.target.value)}
                  placeholder="Value"
                  className="flex-1 px-2 py-1.5 text-xs bg-background border border-border rounded text-text"
                />
                {formRows.length > 1 && (
                  <button onClick={() => setFormRows(formRows.filter((_, i) => i !== idx))}
                    className="text-red-400 hover:text-red-300 text-xs">x</button>
                )}
              </div>
            ))}
            <button
              onClick={() => setFormRows([...formRows, { field: 'hostname', op: 'contains', value: '' }])}
              className="text-xs text-accent hover:text-accent/80"
            >
              + Add condition
            </button>
          </div>

          {/* Generated expression */}
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="text-xs text-muted">Expression:</span>
              <button onClick={() => setShowRawExpr(!showRawExpr)} className="text-[10px] text-accent">
                {showRawExpr ? 'hide raw' : 'show raw'}
              </button>
            </div>
            <div className="px-3 py-2 text-xs bg-background border border-border rounded text-muted font-mono">
              {generateExpression(formRows, formLogic)}
            </div>
            {showRawExpr && (
              <pre className="px-3 py-2 text-[10px] bg-background border border-border rounded text-muted overflow-x-auto">
                {JSON.stringify(conditionRowsToJson(formRows, formLogic), null, 2)}
              </pre>
            )}
          </div>

          {/* Action (routing) or Color+Label (highlight) */}
          {tab === 'routing' ? (
            <div className="space-y-2">
              <span className="text-xs text-muted">Action:</span>
              <div className="flex gap-2">
                {['auto_ack', 'auto_resolve', 'auto_silence', 'auto_escalate'].map(a => (
                  <button
                    key={a}
                    onClick={() => setFormAction(a)}
                    className={`px-3 py-1.5 text-xs rounded border ${formAction === a ? 'bg-accent/20 border-accent text-accent' : 'border-border text-muted hover:text-text'}`}
                  >
                    {a.replace('auto_', 'Auto ')}
                  </button>
                ))}
              </div>
              {formAction === 'auto_silence' && (
                <input
                  placeholder="Duration (e.g. 2h)"
                  value={formActionParams.duration || ''}
                  onChange={e => setFormActionParams({ ...formActionParams, duration: e.target.value })}
                  className="px-2 py-1.5 text-xs bg-background border border-border rounded text-text w-32"
                />
              )}
              {formAction === 'auto_escalate' && (
                <input
                  placeholder="Team name"
                  value={formActionParams.team || ''}
                  onChange={e => setFormActionParams({ ...formActionParams, team: e.target.value })}
                  className="px-2 py-1.5 text-xs bg-background border border-border rounded text-text w-48"
                />
              )}
            </div>
          ) : (
            <div className="space-y-2">
              <div className="grid gap-4 md:grid-cols-[auto,1fr,auto]">
                <div>
                  <span className="text-xs text-muted block mb-1">Color:</span>
                  <div className="flex items-center gap-2">
                    <input
                      type="color"
                      value={previewColor}
                      onChange={e => setFormColor(e.target.value)}
                      className="h-9 w-12 cursor-pointer rounded border border-border bg-background p-1"
                    />
                    <code className="text-xs text-muted">{previewColor}</code>
                  </div>
                </div>
                <div className="flex-1">
                  <span className="text-xs text-muted block mb-1">Label:</span>
                  <input
                    value={formLabel}
                    onChange={e => setFormLabel(e.target.value)}
                    placeholder="e.g. RADIX - CRITICAL"
                    className="px-2 py-1.5 text-xs bg-background border border-border rounded text-text w-full"
                  />
                </div>
                <div>
                  <span className="text-xs text-muted block mb-1">Highlight Mode:</span>
                  <div className="flex gap-2">
                    {([
                      ['side', 'Side Bar'],
                      ['box', 'Full Box'],
                    ] as const).map(([value, label]) => (
                      <button
                        key={value}
                        onClick={() => setFormHighlightStyle(value)}
                        className={`px-3 py-1.5 text-xs rounded border transition-colors ${
                          formHighlightStyle === value
                            ? 'bg-accent/20 border-accent text-accent'
                            : 'border-border text-muted hover:text-text'
                        }`}
                      >
                        {label}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
              {/* Preview */}
              <div
                className="flex items-center gap-2 p-2 rounded border border-border"
                style={formHighlightStyle === 'box' ? {
                  backgroundColor: colorWithAlpha(previewColor, 0.14),
                  boxShadow: `inset 0 0 0 1px ${colorWithAlpha(previewColor, 0.34)}`,
                } : undefined}
              >
                <div className="w-1 h-8 rounded-full" style={{ backgroundColor: previewColor }} />
                <span
                  className="px-1.5 py-0.5 text-[10px] rounded font-medium"
                  style={{
                    backgroundColor: colorWithAlpha(previewColor, 0.18),
                    color: previewColor,
                    border: `1px solid ${colorWithAlpha(previewColor, 0.34)}`,
                  }}
                >
                  {formLabel || 'LABEL'}
                </span>
                <span className="text-xs text-muted">Sample alert name</span>
              </div>
            </div>
          )}

          <button
            onClick={handleSave}
            disabled={saving || !formName}
            className="px-4 py-2 text-xs font-medium bg-accent text-white rounded hover:bg-accent/80 disabled:opacity-50"
          >
            {saving ? 'Saving...' : editingId ? 'Update Rule' : 'Create Rule'}
          </button>
        </div>
      )}

      {/* Rules Table */}
      {loading ? (
        <div className="text-center py-8 text-muted">Loading...</div>
      ) : rules.length === 0 ? (
        <div className="text-center py-8 text-muted">No {tab} rules yet</div>
      ) : (
        <div className="bg-surface border border-border rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-left text-xs text-muted uppercase">
                <th className="px-4 py-2">Name</th>
                <th className="px-4 py-2">Expression</th>
                <th className="px-4 py-2">{tab === 'routing' ? 'Action' : 'Style'}</th>
                <th className="px-4 py-2">Priority</th>
                <th className="px-4 py-2">Enabled</th>
                <th className="px-4 py-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {rules.map(rule => (
                <tr key={rule.id} className="border-b border-border/50 hover:bg-surface-hover">
                  <td className="px-4 py-2 text-text-bright font-medium">{rule.name}</td>
                  <td className="px-4 py-2 text-xs text-muted font-mono max-w-[300px] truncate">
                    {rule.expression_text || JSON.stringify(rule.conditions_json)}
                  </td>
                  <td className="px-4 py-2">
                    {tab === 'routing' ? (
                      <span className="px-2 py-0.5 text-xs bg-blue-900/30 text-blue-400 rounded">
                        {(rule.action || '').replace('auto_', '')}
                      </span>
                    ) : (
                      <div className="flex items-center gap-1">
                        <div className="w-3 h-3 rounded-full" style={{ backgroundColor: normalizeHighlightColor(rule.color) }} />
                        <span className="text-xs text-muted">
                          {(rule.action_params?.highlight_style === 'box' ? 'Full box' : 'Side bar')}
                          {rule.label ? ` · ${rule.label}` : ''}
                        </span>
                      </div>
                    )}
                  </td>
                  <td className="px-4 py-2 text-xs text-muted">{rule.priority}</td>
                  <td className="px-4 py-2">
                    <button
                      onClick={() => handleToggle(rule)}
                      className={`px-2 py-0.5 text-xs rounded ${rule.enabled ? 'bg-green-900/30 text-green-400' : 'bg-gray-900/30 text-gray-500'}`}
                    >
                      {rule.enabled ? 'On' : 'Off'}
                    </button>
                  </td>
                  <td className="px-4 py-2">
                    <div className="flex gap-2">
                      <button onClick={() => openEditForm(rule)} className="text-xs text-accent hover:text-accent/80">Edit</button>
                      <button onClick={() => handleDelete(rule.id, rule.name)} className="text-xs text-red-400 hover:text-red-300">Delete</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default function AlertRulesPage() {
  return <AlertRulesManager />;
}
