export type Tab = { href: string; label: string; perm: string };

export const ADMIN_TABS: Tab[] = [
  { href: '/portal/admin/users',         label: 'Users',         perm: 'manage_users' },
  { href: '/portal/admin/roles',         label: 'Roles',         perm: 'manage_roles' },
  { href: '/portal/admin/ai',            label: 'AI',            perm: 'manage_ai' },
  { href: '/portal/admin/pipeline',      label: 'Pipeline',      perm: 'manage_pipeline' },
  { href: '/portal/admin/zabbix',        label: 'Zabbix',        perm: 'manage_zabbix' },
  { href: '/portal/admin/integrations',  label: 'Integrations',  perm: 'manage_integrations' },
  { href: '/portal/admin/services',      label: 'Services',      perm: 'manage_services' },
  { href: '/portal/admin/features',      label: 'Features',      perm: 'manage_features' },
  { href: '/portal/admin/runbooks',      label: 'Runbooks',      perm: 'manage_runbooks' },
  { href: '/portal/admin/audit',         label: 'Audit',         perm: 'view_audit' },
];
