'use client';

import { StatuspageComponent, StatuspageComponentStatus, StatuspageComponentUpdate } from '@/lib/types';

const STATUS_OPTIONS: Array<{ value: StatuspageComponentStatus; label: string }> = [
  { value: 'operational', label: 'Operational' },
  { value: 'degraded_performance', label: 'Degraded Performance' },
  { value: 'partial_outage', label: 'Partial Outage' },
  { value: 'major_outage', label: 'Major Outage' },
];

export default function StatuspageComponentStatusPicker({
  components,
  value,
  onChange,
}: {
  components: StatuspageComponent[];
  value: StatuspageComponentUpdate[];
  onChange: (next: StatuspageComponentUpdate[]) => void;
}) {
  const valueMap = new Map(value.map(item => [item.component_id, item.status] as const));

  function emit(nextMap: Map<string, StatuspageComponentStatus>) {
    onChange(
      Array.from(nextMap.entries()).map(([component_id, status]) => ({
        component_id,
        status,
      })),
    );
  }

  function toggleComponent(componentId: string, checked: boolean) {
    const next = new Map(valueMap);
    if (!checked) {
      next.delete(componentId);
    } else if (!next.has(componentId)) {
      next.set(componentId, 'degraded_performance');
    }
    emit(next);
  }

  function setComponentStatus(componentId: string, status: StatuspageComponentStatus) {
    const next = new Map(valueMap);
    next.set(componentId, status);
    emit(next);
  }

  return (
    <div className="space-y-2">
      {components.map(component => {
        const selected = valueMap.has(component.id);
        const selectedStatus = valueMap.get(component.id) || 'degraded_performance';

        return (
          <div key={component.id} className="rounded-lg border border-border bg-bg/40 px-3 py-2">
            <div className="flex items-start gap-3">
              <input
                type="checkbox"
                checked={selected}
                onChange={(e) => toggleComponent(component.id, e.target.checked)}
                className="mt-1"
              />
              <div className="min-w-0 flex-1">
                <div className="text-sm text-text-bright">{component.name}</div>
                <div className="text-xs text-muted">{component.description || component.status}</div>
              </div>
              {selected && (
                <select
                  value={selectedStatus}
                  onChange={(e) => setComponentStatus(component.id, e.target.value as StatuspageComponentStatus)}
                  className="bg-surface border border-border rounded px-2 py-1 text-xs text-text"
                >
                  {STATUS_OPTIONS.map(option => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
