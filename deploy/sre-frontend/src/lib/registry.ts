/** Registry contact data sourced from Confluence: Registry Contacts page
 *  https://wiki-tucows.atlassian.net/wiki/spaces/OCC/pages/9376530442/Registry+Contacts */

export interface RegistryContact {
  role: string;
  phone?: string;
  email?: string;
  notes?: string;
}

export interface RegistryOperator {
  id: string;
  name: string;
  tlds: string[];
  type: string;
  contacts: RegistryContact[];
  hours?: string;
  statusPage?: string;
  notes?: string;
}

/** All TLD → operator mappings for quick lookup */
export const TLD_OPERATOR_MAP: Record<string, string> = {
  '.asia': 'identity-digital',
  '.at': 'nic-at',
  '.au': 'afilias-au',
  '.com.au': 'afilias-au',
  '.be': 'dnsbelgium',
  '.biz': 'godaddy-registry',
  '.br': 'registro',
  '.com.br': 'registro',
  '.bz': 'identity-digital',
  '.ca': 'cira',
  '.cc': 'verisign',
  '.ch': 'switch',
  '.cn': 'godaddy-registry',
  '.com.cn': 'godaddy-registry',
  '.co': 'godaddy-registry',
  '.com': 'verisign',
  '.scot': 'corenic',
  '.de': 'denic',
  '.dk': 'punktum-dk',
  '.es': 'red',
  '.eu': 'eurid',
  '.fr': 'afnic',
  '.frl': 'frl-registry',
  '.in': 'identity-digital',
  '.co.in': 'identity-digital',
  '.info': 'identity-digital',
  '.it': 'nicit',
  '.me': 'identity-digital',
  '.mobi': 'identity-digital',
  '.moe': 'godaddy-registry',
  '.mx': 'nic-mx',
  '.com.mx': 'nic-mx',
  '.name': 'verisign',
  '.net': 'verisign',
  '.nl': 'sidn',
  '.nz': 'internetnz',
  '.org': 'pir',
  '.pro': 'registrypro',
  '.shop': 'gmo-registry',
  '.tel': 'godaddy-registry',
  '.tv': 'verisign',
  '.uk': 'nominet',
  '.co.uk': 'nominet',
  '.me.uk': 'nominet',
  '.org.uk': 'nominet',
  '.us': 'godaddy-registry',
  '.ws': 'website-ws',
  '.xxx': 'icmregistry',
};

export const REGISTRY_OPERATORS: RegistryOperator[] = [
  {
    id: 'identity-digital',
    name: 'Identity Digital (Afilias / Donuts)',
    tlds: ['.info', '.asia', '.bz', '.in', '.co.in', '.mobi', '.me'],
    type: 'gTLD/ccTLD',
    contacts: [
      { role: 'Tech Support', phone: '+1.416.646.3306', email: 'techsupport@identity.digital', notes: 'Also try techsupport@afilias.net' },
      { role: 'Tech Support (GRS)', phone: '+1.416.646.3306', email: 'techsupport@afilias-grs.net', notes: 'For .ASIA, .BZ, .IN, .VC' },
      { role: 'Tech Support (.MOBI)', phone: '+1.416.619.3039', email: 'techsupport@registry.mobi' },
      { role: 'Support (.ME)', phone: '+1 416.619.3037', email: 'support@registry.me' },
      { role: 'General (Donuts)', phone: '+1.416.646.3306', email: 'techsupport@identity.digital', notes: 'Germany: 0049 8007 238444, UK: 0800 0124516, USA: 001 888 683 6564' },
    ],
    hours: '24x7x365',
    notes: 'Afilias is Identity Digital. Passphrase for .INFO: pinkmouse. Passphrase for .IN: pink elephant.',
  },
  {
    id: 'verisign',
    name: 'Verisign',
    tlds: ['.com', '.net', '.cc', '.name', '.tv'],
    type: 'gTLD/ccTLD',
    contacts: [
      { role: 'Support', phone: '+1.703.925.6999', email: 'info@verisign-grs.com' },
      { role: 'Account Manager (Tim Switzer)', email: 'tswitzer@verisign.com' },
    ],
    hours: '24x7x365',
    notes: 'Portal: https://nsmanager.verisign-grs.com/ncc',
  },
  {
    id: 'godaddy-registry',
    name: 'GoDaddy Registry (formerly Neustar)',
    tlds: ['.biz', '.cn', '.com.cn', '.co', '.tel', '.us', '.moe'],
    type: 'gTLD/ccTLD',
    contacts: [
      { role: 'Support', phone: '+1 (480) 651-9999', notes: 'Help center: https://helpcenter.registry.godaddy/s/' },
      { role: 'Account Manager (Kathy Nielsen)', email: 'kathy@registry.godaddy' },
      { role: 'Billing', email: 'registry-billing@team.neustar' },
    ],
    hours: '24x7x365',
    statusPage: 'https://status.godaddy.com/',
    notes: 'Passphrase: Pink Elephant',
  },
  {
    id: 'cira',
    name: 'CIRA',
    tlds: ['.ca'],
    type: 'ccTLD',
    contacts: [
      { role: 'Support', phone: '+1.877.860.1411', email: 'regsupport@cira.ca', notes: 'Office hours: 8am-8pm EST Mon-Fri' },
      { role: 'Emergency (After Hours)', email: 'regsupport@cira.ca', notes: 'Use [URGENT] in subject line to activate on-call' },
    ],
    hours: '24x7x365 (with URGENT tag for after-hours)',
    notes: 'Best to email instead of phone. Admin: https://cira2.cira.ca/cira/registraires',
  },
  {
    id: 'denic',
    name: 'DENIC',
    tlds: ['.de'],
    type: 'ccTLD',
    contacts: [
      { role: 'EPAG Team (Outages)', email: 'registry-relations@epag.de', notes: 'OpenSRS .DE outages go through EPAG. Hours: 08:00-18:00 CET. Also #team-epag-ff Slack' },
      { role: 'EPAG Support', email: 'info@epag.de' },
      { role: 'DENIC Emergency', phone: '(011) 49-69-27235-299', email: 'sos@denic.de' },
      { role: 'DENIC Member Services', phone: '+49 69 272 35 290', email: 'dbs@denic.de', notes: 'Office hours from 0600 UTC' },
    ],
    hours: '24x7x365',
    statusPage: 'https://denic.status.io/',
    notes: 'Contact EPAG first for OpenSRS issues. Do not contact registry directly — TLDs require authorized contacts.',
  },
  {
    id: 'nominet',
    name: 'Nominet',
    tlds: ['.uk', '.co.uk', '.me.uk', '.org.uk'],
    type: 'ccTLD',
    contacts: [
      { role: 'Support (8am-6pm UK)', phone: '+44 (0)330 236 9480', email: 'support@nominet.uk', notes: 'Also: hostmaster@nominet.uk' },
      { role: 'Front Line', phone: '+44 (0)1865 332211', email: 'nominet@nominet.uk' },
      { role: 'Emergency/After Hours', phone: '+44(0) 1865 332460', email: 'support@nominet.org.uk', notes: 'Only for registering/renewing domain issues' },
      { role: 'Account Manager (Sophie Corrigan)', phone: '+44 (07917) 552621', email: 'sophie.corrigan@nominet.uk' },
    ],
    hours: '8am-6pm Mon-Fri (UK), emergency 24/7',
    statusPage: 'https://nominetstatus.uk/',
    notes: 'Our tag is "Tucows-ca". Twitter: @nominet_systems',
  },
  {
    id: 'pir',
    name: 'PIR (Public Interest Registry)',
    tlds: ['.org'],
    type: 'gTLD',
    contacts: [
      { role: 'Support', phone: '+1-416-646-3308', notes: 'Toll-free: +1.855-373-0347. Security Passphrase: Blue Donkey' },
      { role: 'Account Manager (Melody Agee)', phone: '+1 703-889-5778', email: 'magee@pir.org', notes: 'Cell: +1 703-717-2630' },
    ],
    hours: '24x7x365',
    notes: 'Send emails using ops.mon@tucows.com. Admin: https://admin.publicinterestregistry.net',
  },
  {
    id: 'afnic',
    name: 'AFNIC',
    tlds: ['.fr'],
    type: 'ccTLD',
    contacts: [
      { role: 'EPAG Team (Outages)', email: 'registry-relations@epag.de', notes: 'Any .FR outages go through EPAG. Hours: 08:00-18:00 CET. Also #team-epag-ff Slack' },
      { role: 'EPAG Support', email: 'info@epag.de' },
      { role: 'AFNIC Direct Support', phone: '+33 139 308 300', email: 'support@afnic.fr', notes: '9am-6pm Paris time Mon-Fri' },
      { role: 'Account Manager (Seline Adega)', email: 'seline.adega-serviceclient@afnic.fr' },
    ],
    hours: '24x7x365',
    statusPage: 'https://www.afnic.fr/en/about-afnic/news/operations-news/',
    notes: 'Do not contact registry directly — TLDs require authorized contacts. Contact EPAG first.',
  },
  {
    id: 'sidn',
    name: 'SIDN',
    tlds: ['.nl'],
    type: 'ccTLD',
    contacts: [
      { role: 'Support', phone: '(011) +31 26 352 55 55', email: 'support@sidn.nl', notes: '8:30am-5:00pm Dutch time' },
      { role: 'Emergency', phone: '(011) +31 26 352 55 98', notes: 'HRS or SRS offline only' },
    ],
    hours: '24x7x365',
    notes: 'Twitter for status: @SIDN, @sidnsupport',
  },
  {
    id: 'eurid',
    name: 'EURid',
    tlds: ['.eu'],
    type: 'ccTLD',
    contacts: [
      { role: 'General Support', phone: '(011) 32 2 401 27 60', email: 'tech@eurid.eu' },
      { role: 'Tech', phone: '(011) 32 2 401 27 79', email: 'tech@eurid.eu' },
      { role: 'Emergency', phone: '+32 (0) 2 725 98 25' },
    ],
    hours: 'Mon-Fri 09:00-17:00 CET',
    notes: 'Check @Euregistry on Twitter before contacting.',
  },
  {
    id: 'nic-at',
    name: 'nic.at',
    tlds: ['.at'],
    type: 'ccTLD',
    contacts: [
      { role: 'Support', phone: '+43.662.46.69.0', email: 'service@nic.at' },
    ],
    hours: '24x7x365',
    notes: 'Tucows NOC waiting to have authorized contacts added.',
  },
  {
    id: 'corenic',
    name: 'Corenic',
    tlds: ['.scot', '.cat'],
    type: 'gTLD',
    contacts: [
      { role: 'Support', phone: '+41 22 312 5610', email: 'tld-support@rs.corenic.net' },
      { role: 'Support (.scot)', email: 'scot-support@rs.corenic.net' },
    ],
    notes: 'Also operates: .CAT, .Barcelona, .Quebec, .Sport, .paris',
  },
  {
    id: 'afilias-au',
    name: 'Afilias (.AU)',
    tlds: ['.au', '.com.au'],
    type: 'ccTLD',
    contacts: [
      { role: 'Support', phone: '+61-3-9021-6914', email: 'support@afilias.com.au', notes: 'North America: +1-416-619-3038' },
      { role: 'Marketing (Greta Adamo)', email: 'gadamo@afilias.com.au' },
      { role: 'Tech (Jitender Kumar)', email: 'jkumar@afilias.info' },
    ],
    hours: '24x7x365',
    notes: 'Afilias is operator, auDA is registry. Portal: https://portal.afilias.info/',
  },
  {
    id: 'punktum-dk',
    name: 'Punktum dk',
    tlds: ['.dk'],
    type: 'ccTLD',
    contacts: [
      { role: 'Support', phone: '+45 51 27 06 75', notes: 'Mon-Thu 9:00-16:00, Fri 9:00-14:00. Contact form: https://punktum.dk/en/contact-customer-service' },
    ],
    statusPage: 'https://punktum.dk/artikler/driftstatus',
  },
  {
    id: 'dnsbelgium',
    name: 'DNSBelgium',
    tlds: ['.be'],
    type: 'ccTLD',
    contacts: [
      { role: 'Support', phone: '+32 16 28 49 70', email: 'support@dnsbelgium.be', notes: 'Also: registrars@dnsbelgium.be' },
    ],
    hours: '8:30-17:00 Mon-Fri',
    statusPage: 'https://www.dnsbelgium.be/en/registrars/maintenance-calendar',
  },
  {
    id: 'red',
    name: 'RED (.ES)',
    tlds: ['.es'],
    type: 'ccTLD',
    contacts: [
      { role: 'Support', phone: '+34 912 750 596', email: 'ar@dominios.es', notes: '8am-8pm UTC+1 Mon-Fri. Phone in Spanish only.' },
      { role: 'Critical 24x7', phone: '+34 91 266 35 79', email: '24x7@dominios.es', notes: 'For platform collapse, DNS resolution, security. Also: soportedominios24x7@red.es' },
      { role: 'Emergency (Alberto Perez)', phone: '+34 600 404 764', email: 'alberto.perez@red.es', notes: 'Deputy Director. Cell for emergency only.' },
    ],
  },
  {
    id: 'registro',
    name: 'Registro (.BR)',
    tlds: ['.br', '.com.br'],
    type: 'ccTLD',
    contacts: [
      { role: 'Primary (Lars Jensen / ToWeb)', phone: '+55 27 9851 0479', email: 'lars@towebbrasil.com' },
      { role: 'Backend (KeySystems)', phone: '+49 (0) 6894 - 9396 870', email: 'support@rrpproxy.net', notes: 'KeySystems will not support us directly — must go through TOWEB.' },
    ],
    notes: 'We connect through Key-Systems, not directly to registry. Main contact is Lars Jensen at Toweb.',
  },
  {
    id: 'nicit',
    name: 'nicIT',
    tlds: ['.it'],
    type: 'ccTLD',
    contacts: [
      { role: 'Support', phone: '+39 050 9719811', email: 'info@nic.it', notes: 'Auth code for Tucows: 11527249' },
      { role: 'Hostmaster', email: 'hostmaster@nic.it', notes: 'For maintainers only' },
    ],
    hours: '9:30am-1pm, 2:30pm-5:30pm',
  },
  {
    id: 'nic-mx',
    name: 'NIC.mx',
    tlds: ['.mx', '.com.mx'],
    type: 'ccTLD',
    contacts: [
      { role: 'Support', phone: '+52 (81) 8387-5346', email: 'help@nic.mx' },
    ],
    notes: 'Tucows NOC waiting to have authorized contacts added.',
  },
  {
    id: 'switch',
    name: 'SWITCH',
    tlds: ['.ch', '.li'],
    type: 'ccTLD',
    contacts: [
      { role: 'Support', phone: '(011) +41 848 844 080', email: 'helpdesk@nic.ch' },
    ],
    hours: 'Mon-Fri 9h-12h and 14h-17h (UTC+1, summer UTC+2)',
  },
  {
    id: 'registrypro',
    name: 'RegistryPro',
    tlds: ['.pro'],
    type: 'gTLD',
    contacts: [
      { role: 'Support / Emergency', phone: '+1 312-994-7652', email: 'support@registry.pro', notes: 'Username: iana-69, Passphrase: pink elephant' },
      { role: 'Escalation (Matt Buckland)', phone: '1 866 441 9512 ext. 250', notes: 'Director of Operations' },
    ],
    hours: '24/7',
  },
  {
    id: 'frl-registry',
    name: 'FRL Registry',
    tlds: ['.frl'],
    type: 'ccTLD',
    contacts: [
      { role: 'Support', phone: '+31.58 7630650', email: 'support@frlregistry.zendesk.com' },
    ],
  },
  {
    id: 'icmregistry',
    name: 'ICM Registry',
    tlds: ['.xxx'],
    type: 'sTLD',
    contacts: [
      { role: 'Support', phone: '+1.855.723.0999', email: 'techsupport@icmregistry.info', notes: 'Passphrase for .XXX: pinkelephant' },
    ],
    hours: '24x7x365',
  },
  {
    id: 'website-ws',
    name: 'WebSite.ws',
    tlds: ['.ws'],
    type: 'ccTLD',
    contacts: [
      { role: 'Support', phone: '+1.760.602.3000', email: 'registrars@website.ws', notes: 'Identify yourself as a Registrar' },
      { role: 'Emergency (Stas Yakovina)', phone: '+1.514.262.6437', email: 'registrars@website.ws', notes: 'IT Director. After hours.' },
      { role: 'Registrar Relations (Heather Binuya)', phone: '+1.760.602.3000 x5710', email: 'heather.binuya@website.ws' },
    ],
    hours: '24x7x365',
  },
  {
    id: 'epag',
    name: 'EPAG',
    tlds: ['200+ ccTLDs'],
    type: 'ccTLD (Special)',
    contacts: [
      { role: 'Development / NOC Support', email: 'entwicklung@epag.de' },
      { role: 'Alex Schertner (Managing Director)', phone: '+49 228 32 96 813', email: 'as@epag.de', notes: 'Toronto: 416-919-7046' },
      { role: 'Martin Urban', phone: '+49 228 32 96 816', email: 'mu@epag.de' },
      { role: 'Ashley La Bolle', phone: '+49 228 32 96 814', email: 'al@epag.de' },
    ],
    hours: 'Mon-Fri 9am-5pm CET',
    notes: 'Email entwicklung@epag.de first. Emergency: Peter Lange +49 1515 712 61 84 (prolonged outage 1hr+ only). Support portal: https://support.epag.de/home (user: ops.mon@tucows.com)',
  },
  {
    id: 'gmo-registry',
    name: 'GMO Registry',
    tlds: ['.shop', '.jp'],
    type: 'gTLD',
    contacts: [
      { role: 'Support', email: 'support@gmoregistry.com' },
    ],
  },
  {
    id: 'zacr',
    name: 'ZACR',
    tlds: ['.za', '.co.za'],
    type: 'ccTLD',
    contacts: [
      { role: 'Support', phone: '+27 11 314 0077', email: 'support@registry.net.za' },
      { role: 'Individual (Mike)', phone: '+27 11 314 0077', email: 'mike@dnservices.co.za' },
    ],
    notes: 'Ticketing: https://support.dnservices.co.za/index.php',
  },
  {
    id: 'uniregistry',
    name: 'UNI Registry',
    tlds: [],
    type: 'sTLD (Special)',
    contacts: [
      { role: 'Support', phone: '1 949 706 2300 ext 4229', email: 'help@uniregistry.com', notes: 'Ticket portal: https://uniregistry.link/contact/' },
    ],
  },
  {
    id: 'ari-registry',
    name: 'ARI Registry',
    tlds: [],
    type: 'gTLD',
    contacts: [
      { role: 'Support', phone: '571 434 6700 opt 1 opt 2 opt 5', email: 'registry-help@registry.godaddy', notes: 'US only: 844 677 2878' },
    ],
    statusPage: 'https://status.godaddy.com/',
  },
  {
    id: 'centralnic',
    name: 'CentralNic',
    tlds: [],
    type: 'gTLD',
    contacts: [
      { role: 'Support', phone: '+44 (0)20 33 88 0600', email: 'info@centralnic.com', notes: 'Also: registrars@centralnic.com' },
    ],
    statusPage: 'https://status.centralnicreseller.com/',
    notes: 'TLD list: https://www.centralnic.com/portfolio/tldlist',
  },
  {
    id: 'minds-machines',
    name: 'Minds + Machines',
    tlds: [],
    type: 'gTLD',
    contacts: [
      { role: 'Support', phone: '+353 (0)1 430 1689', email: 'Support@mm-registry.com', notes: 'Ireland' },
    ],
  },
  {
    id: 'rightside',
    name: 'Rightside',
    tlds: [],
    type: 'gTLD',
    contacts: [
      { role: 'Support', phone: '+353 (0)1 901 2100', email: 'registrartechsupport@rightside.rocks', notes: 'Also: 1 888 683 6562' },
    ],
  },
  {
    id: 'internetnz',
    name: 'InternetNZ',
    tlds: ['.nz'],
    type: 'ccTLD',
    contacts: [],
    statusPage: 'https://status.internetnz.nz/',
  },
  {
    id: 'knet-zdns',
    name: 'Knet Registry (ZDNS)',
    tlds: [],
    type: 'gTLD',
    contacts: [
      { role: 'Tech Support', email: 'tech-support@zdns.cn' },
      { role: 'Lina Yang (Tech)', phone: '+15810714969' },
      { role: 'Sarah Lyu (Account Manager)', email: 'sarah@nic.top' },
    ],
  },
];

/**
 * Patterns that strongly indicate a registry/domain-infrastructure alert.
 * We require the alert name (not hostname/description) to match one of these
 * before we attempt TLD or operator matching. This prevents false positives
 * from generic CPU/memory/process alerts that just happen to have .com in hostname.
 */
const REGISTRY_ALERT_PATTERNS = [
  // Explicit registry connection language
  /registry/i,
  /registrar/i,
  /\bepp\b/i,
  /\bwhois\b/i,
  /\brdap\b/i,
  /\btld\b/i,
  /\bdomain.*(connection|timeout|error|fail|down|unreachable)/i,
  /\b(connection|timeout|error|fail|down|unreachable).*domain/i,
  // Proxy names that indicate registry connectivity
  /euproxy/i,
  /regproxy/i,
  /epp.?proxy/i,
  /srs.?(connection|proxy|gateway)/i,
  // Specific service names that are registry-facing
  /opensrs.*registry/i,
  /ascio.*registry/i,
  /enom.*registry/i,
  /registry.*(connection|timeout|error|fail|down|unreachable|disconnect)/i,
  /(connection|timeout|error|fail|down|unreachable|disconnect).*registry/i,
];

/** Specific operator name patterns — only unique, unambiguous identifiers */
const OPERATOR_NAME_PATTERNS: { pattern: RegExp; operatorId: string }[] = [
  { pattern: /\bverisign\b/i, operatorId: 'verisign' },
  { pattern: /\bafilias\b/i, operatorId: 'identity-digital' },
  { pattern: /\bneustar\b/i, operatorId: 'godaddy-registry' },
  { pattern: /\bnominet\b/i, operatorId: 'nominet' },
  { pattern: /\bcira\b/i, operatorId: 'cira' },
  { pattern: /\bdenic\b/i, operatorId: 'denic' },
  { pattern: /\bsidn\b/i, operatorId: 'sidn' },
  { pattern: /\beurid\b/i, operatorId: 'eurid' },
  { pattern: /\bafnic\b/i, operatorId: 'afnic' },
  { pattern: /\bepag\b/i, operatorId: 'epag' },
  { pattern: /\bidentity.?digital\b/i, operatorId: 'identity-digital' },
  { pattern: /\bcentralnic\b/i, operatorId: 'centralnic' },
  { pattern: /\bdonuts\b/i, operatorId: 'identity-digital' },
  { pattern: /\bpir\b/i, operatorId: 'pir' },
  { pattern: /\bicmregistry\b/i, operatorId: 'icmregistry' },
];

/**
 * TLD extraction — only match TLDs that appear in a registry-relevant context,
 * i.e. the TLD is the subject of the alert, not just part of a hostname.
 * Examples that SHOULD match: "Connection to .EU registry failed", "EUProxy .EU timeout"
 * Examples that should NOT match: "CPU high on server01.prod.com"
 */
const EXPLICIT_TLD_PATTERN = /(?:^|\s)\.(com|net|org|info|biz|name|pro|mobi|tel|asia|xxx|shop|moe|co|cc|tv|us|ws|frl|scot|cat|ca|uk|de|fr|nl|be|eu|es|it|at|ch|li|dk|br|mx|au|in|bz|cn|nz|za)\b/i;

export interface RegistryMatch {
  operator: RegistryOperator;
  matchedTld?: string;
  matchReason: string;
}

/** Attempt to find a matching registry operator from alert text.
 *  Only matches alerts that are clearly about registry/domain infrastructure. */
export function detectRegistryFromAlert(alertName: string, hostname?: string, description?: string): RegistryMatch | null {
  const allText = `${alertName} ${hostname || ''} ${description || ''}`;
  const nameText = alertName;

  // 1. Check if alert name matches a specific operator name (high confidence)
  for (const { pattern, operatorId } of OPERATOR_NAME_PATTERNS) {
    if (pattern.test(allText)) {
      const operator = REGISTRY_OPERATORS.find(o => o.id === operatorId);
      if (operator) {
        return { operator, matchReason: `Registry "${operator.name}" mentioned in alert` };
      }
    }
  }

  // 2. Check if the alert name indicates a registry-related issue
  const isRegistryAlert = REGISTRY_ALERT_PATTERNS.some(p => p.test(nameText));
  if (!isRegistryAlert) {
    // Also check description for strong registry signals, but only specific phrases
    const descHasRegistry = description && /registry|registrar|\bepp\b|euproxy|regproxy/i.test(description);
    if (!descHasRegistry) {
      return null; // Not a registry alert
    }
  }

  // 3. Extract TLD from proxy names in the alert name/description/hostname
  // e.g. "EuProxy connection to registry is down" → "eu" → .eu → EURid
  // e.g. hostname "euproxy-01.prod.tucows.net" → "eu" → .eu → EURid
  const proxyPattern = /\b([a-z]{2,4})proxy\b/i;
  const proxyMatch = nameText.match(proxyPattern)
    || (description && description.match(proxyPattern))
    || (hostname && hostname.match(proxyPattern));
  if (proxyMatch) {
    const possibleTld = '.' + proxyMatch[1].toLowerCase();
    const operatorId = TLD_OPERATOR_MAP[possibleTld];
    if (operatorId) {
      const operator = REGISTRY_OPERATORS.find(o => o.id === operatorId);
      if (operator) {
        return { operator, matchedTld: possibleTld, matchReason: `Registry proxy for ${possibleTld.toUpperCase()}` };
      }
    }
  }

  // 4. Try to extract an explicit TLD reference (e.g. ".EU", ".CA")
  const tldMatch = nameText.match(EXPLICIT_TLD_PATTERN) || (description && description.match(EXPLICIT_TLD_PATTERN));
  if (tldMatch) {
    const tld = '.' + tldMatch[1].toLowerCase();
    const operatorId = TLD_OPERATOR_MAP[tld];
    if (operatorId) {
      const operator = REGISTRY_OPERATORS.find(o => o.id === operatorId);
      if (operator) {
        return { operator, matchedTld: tld, matchReason: `Registry connection issue for ${tld}` };
      }
    }
  }

  // 5. It's a registry alert but we couldn't determine which specific registry
  return null;
}

/** Build a mailto: URL with pre-filled alert details */
export function buildRegistryMailto(
  operator: RegistryOperator,
  contact: RegistryContact,
  alertDetails?: {
    alertName?: string;
    description?: string;
    startTime?: string;
  }
): string | null {
  if (!contact.email) return null;

  const emails = contact.email.split(/[,;]\s*/);
  const to = emails[0].trim();

  let subject = `[Tucows SRE] Issue Report`;
  let body = '';

  if (alertDetails) {
    subject = `[Tucows SRE] ${alertDetails.alertName || 'Alert'} - Issue Report`;
    body = [
      `Hello ${operator.name} Support Team,`,
      '',
      `We are experiencing an issue that may be related to your service.`,
      '',
      `Alert Details:`,
      `- Alert: ${alertDetails.alertName || 'N/A'}`,
      alertDetails.startTime ? `- Started: ${alertDetails.startTime}` : null,
      alertDetails.description ? `- Description: ${alertDetails.description}` : null,
      '',
      `Could you please investigate on your end and let us know if there are any known issues?`,
      '',
      `Thank you,`,
      `Tucows Domains SRE Team`,
    ].filter(l => l !== null).join('\n');
  } else {
    body = [
      `Hello ${operator.name} Support Team,`,
      '',
      `We are contacting you regarding an issue with our service.`,
      '',
      `[Please describe the issue here]`,
      '',
      `Thank you,`,
      `Tucows Domains SRE Team`,
    ].join('\n');
  }

  return `mailto:${encodeURIComponent(to)}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
}
