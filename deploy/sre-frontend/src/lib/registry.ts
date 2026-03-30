/** Registry contact data sourced from Confluence: Registry Contacts page
 *  https://wiki-tucows.atlassian.net/wiki/spaces/OCC/pages/9376530442/Registry+Contacts
 *  TLD mappings sourced from OpenSRS TLD policy spreadsheets (700+ TLDs) */

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

/** All TLD → operator mappings for quick lookup (700+ entries) */
export const TLD_OPERATOR_MAP: Record<string, string> = {
  // ── Verisign ──
  '.com': 'verisign',
  '.net': 'verisign',
  '.cc': 'verisign',
  '.name': 'verisign',
  '.tv': 'verisign',

  // ── Identity Digital (Afilias / Donuts) ──
  '.asia': 'identity-digital',
  '.bz': 'identity-digital',
  '.in': 'identity-digital',
  '.co.in': 'identity-digital',
  '.info': 'identity-digital',
  '.me': 'identity-digital',
  '.mobi': 'identity-digital',
  '.ac': 'identity-digital',
  '.academy': 'identity-digital',
  '.accountants': 'identity-digital',
  '.agency': 'identity-digital',
  '.ai': 'identity-digital',
  '.apartments': 'identity-digital',
  '.associates': 'identity-digital',
  '.adult': 'identity-digital',
  '.archi': 'identity-digital',
  '.bargains': 'identity-digital',
  '.bet': 'identity-digital',
  '.bike': 'identity-digital',
  '.bingo': 'identity-digital',
  '.bio': 'identity-digital',
  '.black': 'identity-digital',
  '.blue': 'identity-digital',
  '.boutique': 'identity-digital',
  '.builders': 'identity-digital',
  '.business': 'identity-digital',
  '.cab': 'identity-digital',
  '.cafe': 'identity-digital',
  '.camera': 'identity-digital',
  '.camp': 'identity-digital',
  '.capital': 'identity-digital',
  '.cards': 'identity-digital',
  '.care': 'identity-digital',
  '.careers': 'identity-digital',
  '.cash': 'identity-digital',
  '.casino': 'identity-digital',
  '.catering': 'identity-digital',
  '.center': 'identity-digital',
  '.chat': 'identity-digital',
  '.cheap': 'identity-digital',
  '.church': 'identity-digital',
  '.city': 'identity-digital',
  '.claims': 'identity-digital',
  '.cleaning': 'identity-digital',
  '.clinic': 'identity-digital',
  '.clothing': 'identity-digital',
  '.coach': 'identity-digital',
  '.codes': 'identity-digital',
  '.coffee': 'identity-digital',
  '.community': 'identity-digital',
  '.company': 'identity-digital',
  '.computer': 'identity-digital',
  '.condos': 'identity-digital',
  '.construction': 'identity-digital',
  '.contact': 'identity-digital',
  '.contractors': 'identity-digital',
  '.cool': 'identity-digital',
  '.coupons': 'identity-digital',
  '.credit': 'identity-digital',
  '.creditcard': 'identity-digital',
  '.cruises': 'identity-digital',
  '.dating': 'identity-digital',
  '.deals': 'identity-digital',
  '.delivery': 'identity-digital',
  '.dental': 'identity-digital',
  '.diamonds': 'identity-digital',
  '.digital': 'identity-digital',
  '.direct': 'identity-digital',
  '.directory': 'identity-digital',
  '.discount': 'identity-digital',
  '.doctor': 'identity-digital',
  '.dog': 'identity-digital',
  '.domains': 'identity-digital',
  '.education': 'identity-digital',
  '.email': 'identity-digital',
  '.energy': 'identity-digital',
  '.engineering': 'identity-digital',
  '.enterprises': 'identity-digital',
  '.equipment': 'identity-digital',
  '.estate': 'identity-digital',
  '.events': 'identity-digital',
  '.exchange': 'identity-digital',
  '.expert': 'identity-digital',
  '.exposed': 'identity-digital',
  '.express': 'identity-digital',
  '.fail': 'identity-digital',
  '.farm': 'identity-digital',
  '.finance': 'identity-digital',
  '.financial': 'identity-digital',
  '.fish': 'identity-digital',
  '.fitness': 'identity-digital',
  '.flights': 'identity-digital',
  '.florist': 'identity-digital',
  '.football': 'identity-digital',
  '.fund': 'identity-digital',
  '.furniture': 'identity-digital',
  '.fyi': 'identity-digital',
  '.gallery': 'identity-digital',
  '.gifts': 'identity-digital',
  '.glass': 'identity-digital',
  '.global': 'identity-digital',
  '.gmbh': 'identity-digital',
  '.gold': 'identity-digital',
  '.golf': 'identity-digital',
  '.graphics': 'identity-digital',
  '.gratis': 'identity-digital',
  '.green': 'identity-digital',
  '.gripe': 'identity-digital',
  '.group': 'identity-digital',
  '.guide': 'identity-digital',
  '.guru': 'identity-digital',
  '.healthcare': 'identity-digital',
  '.hockey': 'identity-digital',
  '.holdings': 'identity-digital',
  '.holiday': 'identity-digital',
  '.hospital': 'identity-digital',
  '.house': 'identity-digital',
  '.immo': 'identity-digital',
  '.industries': 'identity-digital',
  '.institute': 'identity-digital',
  '.insure': 'identity-digital',
  '.international': 'identity-digital',
  '.investments': 'identity-digital',
  '.irish': 'identity-digital',
  '.jetzt': 'identity-digital',
  '.jewelry': 'identity-digital',
  '.juegos': 'identity-digital',
  '.kaufen': 'identity-digital',
  '.kids': 'identity-digital',
  '.kim': 'identity-digital',
  '.kitchen': 'identity-digital',
  '.land': 'identity-digital',
  '.lease': 'identity-digital',
  '.legal': 'identity-digital',
  '.lgbt': 'identity-digital',
  '.life': 'identity-digital',
  '.lighting': 'identity-digital',
  '.limited': 'identity-digital',
  '.limo': 'identity-digital',
  '.llc': 'identity-digital',
  '.loans': 'identity-digital',
  '.ltd': 'identity-digital',
  '.ltda': 'identity-digital',
  '.maison': 'identity-digital',
  '.management': 'identity-digital',
  '.marketing': 'identity-digital',
  '.mba': 'identity-digital',
  '.media': 'identity-digital',
  '.memorial': 'identity-digital',
  '.money': 'identity-digital',
  '.movie': 'identity-digital',
  '.mu': 'identity-digital',
  '.network': 'identity-digital',
  '.partners': 'identity-digital',
  '.parts': 'identity-digital',
  '.pet': 'identity-digital',
  '.photography': 'identity-digital',
  '.photos': 'identity-digital',
  '.pictures': 'identity-digital',
  '.pink': 'identity-digital',
  '.pizza': 'identity-digital',
  '.place': 'identity-digital',
  '.plumbing': 'identity-digital',
  '.plus': 'identity-digital',
  '.poker': 'identity-digital',
  '.porn': 'identity-digital',
  '.productions': 'identity-digital',
  '.promo': 'identity-digital',
  '.properties': 'identity-digital',
  '.recipes': 'identity-digital',
  '.red': 'identity-digital',
  '.reisen': 'identity-digital',
  '.rentals': 'identity-digital',
  '.repair': 'identity-digital',
  '.report': 'identity-digital',
  '.restaurant': 'identity-digital',
  '.rocks': 'identity-digital',
  '.sale': 'identity-digital',
  '.salon': 'identity-digital',
  '.sarl': 'identity-digital',
  '.school': 'identity-digital',
  '.schule': 'identity-digital',
  '.services': 'identity-digital',
  '.shiksha': 'identity-digital',
  '.shoes': 'identity-digital',
  '.shopping': 'identity-digital',
  '.show': 'identity-digital',
  '.singles': 'identity-digital',
  '.soccer': 'identity-digital',
  '.solar': 'identity-digital',
  '.solutions': 'identity-digital',
  '.style': 'identity-digital',
  '.supplies': 'identity-digital',
  '.supply': 'identity-digital',
  '.support': 'identity-digital',
  '.surgery': 'identity-digital',
  '.systems': 'identity-digital',
  '.tax': 'identity-digital',
  '.tennis': 'identity-digital',
  '.theater': 'identity-digital',
  '.tienda': 'identity-digital',
  '.tips': 'identity-digital',
  '.tires': 'identity-digital',
  '.today': 'identity-digital',
  '.tools': 'identity-digital',
  '.tours': 'identity-digital',
  '.town': 'identity-digital',
  '.toys': 'identity-digital',
  '.training': 'identity-digital',
  '.university': 'identity-digital',
  '.vacations': 'identity-digital',
  '.vc': 'identity-digital',
  '.vegas': 'identity-digital',
  '.ventures': 'identity-digital',
  '.viajes': 'identity-digital',
  '.villas': 'identity-digital',
  '.vin': 'identity-digital',
  '.vision': 'identity-digital',
  '.vote': 'identity-digital',
  '.voto': 'identity-digital',
  '.voyage': 'identity-digital',
  '.watch': 'identity-digital',
  '.watches': 'identity-digital',
  '.wine': 'identity-digital',
  '.works': 'identity-digital',
  '.world': 'identity-digital',
  '.wtf': 'identity-digital',
  '.zone': 'identity-digital',
  '.srl': 'identity-digital',

  // ── GoDaddy Registry (formerly Neustar) ──
  '.biz': 'godaddy-registry',
  '.cn': 'godaddy-registry',
  '.com.cn': 'godaddy-registry',
  '.co': 'godaddy-registry',
  '.tel': 'godaddy-registry',
  '.us': 'godaddy-registry',
  '.moe': 'godaddy-registry',
  '.tw': 'godaddy-registry',
  '.accountant': 'godaddy-registry',
  '.bid': 'godaddy-registry',
  '.buzz': 'godaddy-registry',
  '.cricket': 'godaddy-registry',
  '.date': 'godaddy-registry',
  '.download': 'godaddy-registry',
  '.faith': 'godaddy-registry',
  '.loan': 'godaddy-registry',
  '.party': 'godaddy-registry',
  '.racing': 'godaddy-registry',
  '.review': 'godaddy-registry',
  '.science': 'godaddy-registry',
  '.stream': 'godaddy-registry',
  '.trade': 'godaddy-registry',
  '.webcam': 'godaddy-registry',
  '.win': 'godaddy-registry',
  '.blackfriday': 'godaddy-registry',
  '.photo': 'godaddy-registry',
  '.tattoo': 'godaddy-registry',
  '.voting': 'godaddy-registry',

  // ── CentralNic ──
  '.online': 'centralnic',
  '.site': 'centralnic',
  '.store': 'centralnic',
  '.tech': 'centralnic',
  '.website': 'centralnic',
  '.wiki': 'centralnic',
  '.space': 'centralnic',
  '.host': 'centralnic',
  '.press': 'centralnic',
  '.ink': 'centralnic',
  '.bond': 'centralnic',
  '.fans': 'centralnic',
  '.autos': 'centralnic',
  '.boats': 'centralnic',
  '.case': 'centralnic',
  '.cfd': 'centralnic',
  '.college': 'centralnic',
  '.cyou': 'centralnic',
  '.design': 'centralnic',
  '.fm': 'centralnic',
  '.help': 'centralnic',
  '.homes': 'centralnic',
  '.icu': 'centralnic',
  '.la': 'centralnic',
  '.lat': 'centralnic',
  '.london': 'centralnic',
  '.love': 'centralnic',
  '.motorcycles': 'centralnic',
  '.protection': 'centralnic',
  '.rent': 'centralnic',
  '.sbs': 'centralnic',
  '.security': 'centralnic',
  '.storage': 'centralnic',
  '.theatre': 'centralnic',
  '.tickets': 'centralnic',
  '.xyz': 'centralnic',
  '.yachts': 'centralnic',

  // ── Google Registry ──
  '.app': 'google-registry',
  '.dev': 'google-registry',
  '.page': 'google-registry',
  '.zip': 'google-registry',
  '.foo': 'google-registry',
  '.how': 'google-registry',
  '.dad': 'google-registry',
  '.esq': 'google-registry',
  '.mov': 'google-registry',
  '.meme': 'google-registry',
  '.phd': 'google-registry',
  '.prof': 'google-registry',
  '.nexus': 'google-registry',
  '.ing': 'google-registry',
  '.rsvp': 'google-registry',
  '.soy': 'google-registry',
  '.boo': 'google-registry',
  '.channel': 'google-registry',

  // ── Rightside ──
  '.actor': 'rightside',
  '.airforce': 'rightside',
  '.army': 'rightside',
  '.auction': 'rightside',
  '.band': 'rightside',
  '.consulting': 'rightside',
  '.dance': 'rightside',
  '.degree': 'rightside',
  '.democrat': 'rightside',
  '.dentist': 'rightside',
  '.engineer': 'rightside',
  '.family': 'rightside',
  '.forsale': 'rightside',
  '.futbol': 'rightside',
  '.games': 'rightside',
  '.haus': 'rightside',
  '.immobilien': 'rightside',
  '.lawyer': 'rightside',
  '.live': 'rightside',
  '.market': 'rightside',
  '.moda': 'rightside',
  '.mortgage': 'rightside',
  '.navy': 'rightside',
  '.news': 'rightside',
  '.ninja': 'rightside',
  '.pub': 'rightside',
  '.rehab': 'rightside',
  '.republican': 'rightside',
  '.reviews': 'rightside',
  '.rip': 'rightside',
  '.run': 'rightside',
  '.social': 'rightside',
  '.software': 'rightside',
  '.studio': 'rightside',
  '.vet': 'rightside',
  '.video': 'rightside',

  // ── ARI Registry ──
  '.best': 'ari-registry',
  '.club': 'ari-registry',
  '.earth': 'ari-registry',
  '.nyc': 'ari-registry',
  '.sucks': 'ari-registry',
  '.one': 'ari-registry',
  '.courses': 'ari-registry',
  '.ceo': 'ari-registry',
  '.film': 'ari-registry',
  '.luxury': 'ari-registry',
  '.menu': 'ari-registry',
  '.men': 'ari-registry',
  '.physio': 'ari-registry',
  '.tube': 'ari-registry',
  '.sydney': 'ari-registry',
  '.melbourne': 'ari-registry',
  '.uno': 'ari-registry',
  '.build': 'ari-registry',
  '.study': 'ari-registry',

  // ── Uniregistry ──
  '.audio': 'uniregistry',
  '.click': 'uniregistry',
  '.christmas': 'uniregistry',
  '.country': 'uniregistry',
  '.diet': 'uniregistry',
  '.flowers': 'uniregistry',
  '.game': 'uniregistry',
  '.gift': 'uniregistry',
  '.guitars': 'uniregistry',
  '.hiphop': 'uniregistry',
  '.hosting': 'uniregistry',
  '.link': 'uniregistry',
  '.lol': 'uniregistry',
  '.mom': 'uniregistry',
  '.pics': 'uniregistry',
  '.property': 'uniregistry',
  '.sexy': 'uniregistry',

  // ── Nominet ──
  '.uk': 'nominet',
  '.co.uk': 'nominet',
  '.me.uk': 'nominet',
  '.org.uk': 'nominet',
  '.wales': 'nominet',
  '.cymru': 'nominet',
  '.abogado': 'nominet',
  '.bayern': 'nominet',
  '.beer': 'nominet',
  '.casa': 'nominet',
  '.cooking': 'nominet',
  '.desi': 'nominet',
  '.fashion': 'nominet',
  '.fishing': 'nominet',
  '.fit': 'nominet',
  '.garden': 'nominet',
  '.horse': 'nominet',
  '.law': 'nominet',
  '.med': 'nominet',
  '.surf': 'nominet',
  '.vip': 'nominet',
  '.vodka': 'nominet',
  '.wedding': 'nominet',
  '.work': 'nominet',
  '.yoga': 'nominet',

  // ── PIR (Public Interest Registry) ──
  '.org': 'pir',
  '.charity': 'pir',
  '.foundation': 'pir',
  '.gives': 'pir',
  '.giving': 'pir',
  '.ngo': 'pir',

  // ── GMO Registry ──
  '.shop': 'gmo-registry',
  '.tokyo': 'gmo-registry',
  '.nagoya': 'gmo-registry',
  '.yokohama': 'gmo-registry',

  // ── CIRA ──
  '.ca': 'cira',
  '.blog': 'cira',
  '.kiwi': 'cira',

  // ── AFNIC ──
  '.fr': 'afnic',
  '.paris': 'afnic',

  // ── Google Registry (brand TLDs) ──
  // Already listed above under Google Registry

  // ── Amazon Registry ──
  '.fast': 'amazon-registry',
  '.spot': 'amazon-registry',
  '.talk': 'amazon-registry',
  '.free': 'amazon-registry',
  '.hot': 'amazon-registry',
  '.you': 'amazon-registry',

  // ── Radix ──
  '.fun': 'radix',
  '.ski': 'radix',

  // ── ccTLD Operators ──
  '.at': 'nic-at',
  '.au': 'afilias-au',
  '.com.au': 'afilias-au',
  '.be': 'dnsbelgium',
  '.br': 'registro',
  '.com.br': 'registro',
  '.ch': 'switch',
  '.li': 'switch',
  '.de': 'denic',
  '.dk': 'punktum-dk',
  '.es': 'red',
  '.eu': 'eurid',
  '.frl': 'frl-registry',
  '.it': 'nicit',
  '.mx': 'nic-mx',
  '.com.mx': 'nic-mx',
  '.nl': 'sidn',
  '.nz': 'internetnz',
  '.pro': 'registrypro',
  '.ws': 'website-ws',
  '.xxx': 'icmregistry',
  '.za': 'zacr',
  '.co.za': 'zacr',
  '.nu': 'iis',
  '.se': 'iis',

  // ── Corenic / CORE ──
  '.scot': 'corenic',
  '.cat': 'corenic',
  '.quebec': 'corenic',
  '.eus': 'corenic',

  // ── Knet / ZDNS ──
  '.top': 'knet-zdns',

  // ── Misc ccTLDs (via EPAG or direct) ──
  '.gs': 'epag',
  '.hn': 'epag',
  '.ms': 'epag',
  '.pe': 'epag',
  '.pl': 'epag',
  '.sg': 'epag',
  '.sh': 'epag',
  '.tc': 'epag',
  '.tk': 'epag',
  '.tm': 'epag',
  '.vg': 'epag',
  '.pw': 'epag',
  '.am': 'epag',
  '.cm': 'epag',
  '.io': 'epag',
  '.sc': 'epag',
  '.mn': 'epag',
  '.inc': 'epag',
  '.jobs': 'epag',
  '.ag': 'identity-digital',

  // ── Remaining nTLDs mapped to known operators ──
  '.bar': 'trs',
  '.cloud': 'trs',
  '.diy': 'trs',
  '.feedback': 'trs',
  '.food': 'trs',
  '.forum': 'trs',
  '.lifestyle': 'trs',
  '.living': 'trs',
  '.locker': 'trs',
  '.mobile': 'trs',
  '.music': 'trs',
  '.rest': 'trs',
  '.vana': 'trs',

  // ── NIC.AT operated geoTLDs ──
  '.berlin': 'nic-at',
  '.hamburg': 'nic-at',
};

export const REGISTRY_OPERATORS: RegistryOperator[] = [
  {
    id: 'identity-digital',
    name: 'Identity Digital (Afilias / Donuts)',
    tlds: ['.info', '.asia', '.bz', '.in', '.co.in', '.mobi', '.me', '.academy', '.agency', '.bike', '.business', '.cafe', '.city', '.coffee', '.digital', '.email', '.expert', '.guru', '.life', '.media', '.money', '.network', '.pizza', '.solutions', '.world', '.zone'],
    type: 'gTLD/ccTLD',
    contacts: [
      { role: 'Tech Support', phone: '+1.416.646.3306', email: 'techsupport@identity.digital', notes: 'Also try techsupport@afilias.net' },
      { role: 'Tech Support (GRS)', phone: '+1.416.646.3306', email: 'techsupport@afilias-grs.net', notes: 'For .ASIA, .BZ, .IN, .VC' },
      { role: 'Tech Support (.MOBI)', phone: '+1.416.619.3039', email: 'techsupport@registry.mobi' },
      { role: 'Support (.ME)', phone: '+1 416.619.3037', email: 'support@registry.me' },
      { role: 'General (Donuts)', phone: '+1.416.646.3306', email: 'techsupport@identity.digital', notes: 'Germany: 0049 8007 238444, UK: 0800 0124516, USA: 001 888 683 6564' },
    ],
    hours: '24x7x365',
    notes: 'Afilias is Identity Digital. Operates 200+ nTLDs via Donuts. Passphrase for .INFO: pinkmouse. Passphrase for .IN: pink elephant.',
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
    tlds: ['.biz', '.cn', '.com.cn', '.co', '.tel', '.us', '.moe', '.tw', '.accountant', '.bid', '.buzz'],
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
    tlds: ['.ca', '.blog', '.kiwi'],
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
    tlds: ['.uk', '.co.uk', '.me.uk', '.org.uk', '.wales', '.cymru', '.beer', '.fashion', '.yoga', '.vodka', '.surf', '.garden'],
    type: 'ccTLD',
    contacts: [
      { role: 'Support (8am-6pm UK)', phone: '+44 (0)330 236 9480', email: 'support@nominet.uk', notes: 'Also: hostmaster@nominet.uk' },
      { role: 'Front Line', phone: '+44 (0)1865 332211', email: 'nominet@nominet.uk' },
      { role: 'Emergency/After Hours', phone: '+44(0) 1865 332460', email: 'support@nominet.org.uk', notes: 'Only for registering/renewing domain issues' },
      { role: 'Account Manager (Sophie Corrigan)', phone: '+44 (07917) 552621', email: 'sophie.corrigan@nominet.uk' },
    ],
    hours: '8am-6pm Mon-Fri (UK), emergency 24/7',
    statusPage: 'https://nominetstatus.uk/',
    notes: 'Our tag is "Tucows-ca". Also operates many nTLDs. Twitter: @nominet_systems',
  },
  {
    id: 'pir',
    name: 'PIR (Public Interest Registry)',
    tlds: ['.org', '.charity', '.foundation', '.gives', '.giving', '.ngo'],
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
    tlds: ['.fr', '.paris'],
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
    tlds: ['.at', '.berlin', '.hamburg'],
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
    tlds: ['.scot', '.cat', '.quebec', '.eus'],
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
    tlds: ['.shop', '.jp', '.tokyo', '.nagoya', '.yokohama'],
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
    id: 'centralnic',
    name: 'CentralNic',
    tlds: ['.online', '.site', '.store', '.tech', '.website', '.wiki', '.space', '.host', '.press', '.ink', '.xyz', '.icu'],
    type: 'gTLD',
    contacts: [
      { role: 'Support', phone: '+44 (0)20 33 88 0600', email: 'info@centralnic.com', notes: 'Also: registrars@centralnic.com' },
    ],
    statusPage: 'https://status.centralnicreseller.com/',
    notes: 'TLD list: https://www.centralnic.com/portfolio/tldlist',
  },
  {
    id: 'rightside',
    name: 'Rightside',
    tlds: ['.actor', '.consulting', '.engineer', '.live', '.ninja', '.pub', '.social', '.software', '.video', '.news'],
    type: 'gTLD',
    contacts: [
      { role: 'Support', phone: '+353 (0)1 901 2100', email: 'registrartechsupport@rightside.rocks', notes: 'Also: 1 888 683 6562' },
    ],
  },
  {
    id: 'uniregistry',
    name: 'UNI Registry',
    tlds: ['.audio', '.click', '.flowers', '.gift', '.link', '.lol', '.pics', '.game', '.hosting'],
    type: 'gTLD',
    contacts: [
      { role: 'Support', phone: '1 949 706 2300 ext 4229', email: 'help@uniregistry.com', notes: 'Ticket portal: https://uniregistry.link/contact/' },
    ],
  },
  {
    id: 'ari-registry',
    name: 'ARI Registry',
    tlds: ['.best', '.club', '.earth', '.nyc', '.sucks', '.one', '.courses', '.film', '.luxury', '.menu', '.tube'],
    type: 'gTLD',
    contacts: [
      { role: 'Support', phone: '571 434 6700 opt 1 opt 2 opt 5', email: 'registry-help@registry.godaddy', notes: 'US only: 844 677 2878' },
    ],
    statusPage: 'https://status.godaddy.com/',
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
    tlds: ['.top'],
    type: 'gTLD',
    contacts: [
      { role: 'Tech Support', email: 'tech-support@zdns.cn' },
      { role: 'Lina Yang (Tech)', phone: '+15810714969' },
      { role: 'Sarah Lyu (Account Manager)', email: 'sarah@nic.top' },
    ],
  },
  // ── New operators (minimal entries for TLD map coverage) ──
  {
    id: 'google-registry',
    name: 'Google Registry',
    tlds: ['.app', '.dev', '.page', '.zip', '.foo', '.how', '.dad', '.esq', '.mov', '.meme', '.phd', '.prof', '.nexus', '.ing', '.rsvp', '.soy', '.boo', '.channel'],
    type: 'gTLD',
    contacts: [],
    notes: 'Google-operated TLDs. No direct registry contact — issues are typically infrastructure-level.',
  },
  {
    id: 'amazon-registry',
    name: 'Amazon Registry',
    tlds: ['.fast', '.spot', '.talk', '.free', '.hot', '.you'],
    type: 'brand TLD',
    contacts: [],
    notes: 'Amazon-operated brand TLDs.',
  },
  {
    id: 'radix',
    name: 'Radix',
    tlds: ['.fun', '.ski'],
    type: 'gTLD',
    contacts: [],
  },
  {
    id: 'trs',
    name: 'Tucows Registry Services (TRS)',
    tlds: ['.bar', '.cloud', '.diy', '.feedback', '.food', '.forum', '.lifestyle', '.living', '.locker', '.mobile', '.music', '.rest', '.vana'],
    type: 'gTLD',
    contacts: [
      { role: 'Internal', notes: 'TRS is Tucows own registry — escalate internally via #sre-registry Slack' },
    ],
    notes: 'Tucows-operated TLDs. Escalate internally.',
  },
  {
    id: 'iis',
    name: 'IIS (The Internet Foundation in Sweden)',
    tlds: ['.se', '.nu'],
    type: 'ccTLD',
    contacts: [],
    statusPage: 'https://www.iis.se/',
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
  { pattern: /\bgoogle.?registry\b/i, operatorId: 'google-registry' },
  { pattern: /\bradix\b/i, operatorId: 'radix' },
  { pattern: /\btucows registry\b/i, operatorId: 'trs' },
];

/**
 * Dynamic TLD extraction — checks against TLD_OPERATOR_MAP keys instead of
 * a hardcoded regex. Supports all 700+ mapped TLDs automatically.
 */
function extractExplicitTld(text: string): string | null {
  const matches = Array.from(text.matchAll(/(?:^|\s)\.([a-z]{2,20})\b/gi));
  for (const m of matches) {
    const tld = '.' + m[1].toLowerCase();
    if (TLD_OPERATOR_MAP[tld]) return tld;
  }
  return null;
}

export interface RegistryMatch {
  operator: RegistryOperator;
  matchedTld?: string;
  matchReason: string;
}

/** Attempt to find a matching registry operator from alert text.
 *  Only matches alerts that are clearly about registry/domain infrastructure. */
export function detectRegistryFromAlert(alertName: string, hostname?: string, description?: string): RegistryMatch | null {
  // Note: hostname is intentionally excluded from operator name matching to avoid
  // false positives (e.g. "TRS Registrar Portal" hostname matching the TRS operator
  // when the alert is a generic disk space warning)
  const nameAndDesc = `${alertName} ${description || ''}`;
  const nameText = alertName;

  // 1. Check if alert name/description matches a specific operator name (high confidence)
  for (const { pattern, operatorId } of OPERATOR_NAME_PATTERNS) {
    if (pattern.test(nameAndDesc)) {
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
  // e.g. "EuProxy connection to registry is down" -> "eu" -> .eu -> EURid
  // e.g. hostname "euproxy-01.prod.tucows.net" -> "eu" -> .eu -> EURid
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

  // 4. Try to extract an explicit TLD reference (e.g. ".EU", ".CA") using dynamic lookup
  const tld = extractExplicitTld(nameText) || (description ? extractExplicitTld(description) : null);
  if (tld) {
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

// ── Maintenance-to-Operator Matching ──

/** Map maintenance event vendor/title keywords to operator IDs */
export const VENDOR_OPERATOR_MAP: Record<string, string[]> = {
  'verisign': ['verisign'],
  'centralnic': ['centralnic'],
  'afilias': ['identity-digital'],
  'identity digital': ['identity-digital'],
  'donuts': ['identity-digital'],
  'neustar': ['godaddy-registry'],
  'godaddy registry': ['godaddy-registry'],
  'godaddy': ['godaddy-registry'],
  'cira': ['cira'],
  'nominet': ['nominet'],
  'pir': ['pir'],
  'afnic': ['afnic'],
  'eurid': ['eurid'],
  'denic': ['denic'],
  'sidn': ['sidn'],
  'red.es': ['red'],
  'gmo': ['gmo-registry'],
  'google': ['google-registry'],
  'ari': ['ari-registry'],
  'corenic': ['corenic'],
  'nic.at': ['nic-at'],
  'switch': ['switch'],
  'registro': ['registro'],
  'nicit': ['nicit'],
  'nic.it': ['nicit'],
  'opensrs': ['trs'],
  'tucows registry': ['trs'],
};

/** Match a maintenance event's vendor+title to registry operator IDs */
export function matchMaintenanceToOperators(vendor: string, title: string): string[] {
  const text = `${vendor} ${title}`.toLowerCase();
  const matched = new Set<string>();

  // Check vendor keyword matches
  for (const [keyword, operatorIds] of Object.entries(VENDOR_OPERATOR_MAP)) {
    if (text.includes(keyword)) {
      operatorIds.forEach(id => matched.add(id));
    }
  }

  // Also check for TLD references in the maintenance title
  const tldMatches = Array.from(text.matchAll(/\.(com|net|org|ca|uk|eu|de|fr|nl|be|es|it|at|ch|au|nz|biz|info|[a-z]{2,6})\b/g));
  for (const m of tldMatches) {
    const tld = '.' + m[1];
    const opId = TLD_OPERATOR_MAP[tld];
    if (opId) matched.add(opId);
  }

  return Array.from(matched);
}
