/** Shared country list — dial codes used to validate shop phones. */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) {
    module.exports = api;
  } else {
    root.NexusCountries = api;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  const COUNTRIES = [
    { code: 'ZM', name: 'Zambia', dial: '260' },
    { code: 'ZA', name: 'South Africa', dial: '27' },
    { code: 'ZW', name: 'Zimbabwe', dial: '263' },
    { code: 'MW', name: 'Malawi', dial: '265' },
    { code: 'BW', name: 'Botswana', dial: '267' },
    { code: 'NA', name: 'Namibia', dial: '264' },
    { code: 'MZ', name: 'Mozambique', dial: '258' },
    { code: 'AO', name: 'Angola', dial: '244' },
    { code: 'TZ', name: 'Tanzania', dial: '255' },
    { code: 'KE', name: 'Kenya', dial: '254' },
    { code: 'UG', name: 'Uganda', dial: '256' },
    { code: 'RW', name: 'Rwanda', dial: '250' },
    { code: 'NG', name: 'Nigeria', dial: '234' },
    { code: 'GH', name: 'Ghana', dial: '233' },
    { code: 'EG', name: 'Egypt', dial: '20' },
    { code: 'MA', name: 'Morocco', dial: '212' },
    { code: 'IN', name: 'India', dial: '91' },
    { code: 'PK', name: 'Pakistan', dial: '92' },
    { code: 'BD', name: 'Bangladesh', dial: '880' },
    { code: 'PH', name: 'Philippines', dial: '63' },
    { code: 'ID', name: 'Indonesia', dial: '62' },
    { code: 'BR', name: 'Brazil', dial: '55' },
    { code: 'MX', name: 'Mexico', dial: '52' },
    { code: 'US', name: 'United States', dial: '1' },
    { code: 'CA', name: 'Canada', dial: '1' },
    { code: 'GB', name: 'United Kingdom', dial: '44' },
    { code: 'DE', name: 'Germany', dial: '49' },
    { code: 'FR', name: 'France', dial: '33' },
    { code: 'AE', name: 'United Arab Emirates', dial: '971' },
    { code: 'CN', name: 'China', dial: '86' },
    { code: 'AU', name: 'Australia', dial: '61' },
  ];

  function findByCode(code) {
    const c = String(code || '').toUpperCase();
    return COUNTRIES.find((x) => x.code === c) || null;
  }

  function findByName(name) {
    const n = String(name || '').trim().toLowerCase();
    return COUNTRIES.find((x) => x.name.toLowerCase() === n) || null;
  }

  function resolveCountry(value) {
    if (!value) return null;
    return findByCode(value) || findByName(value);
  }

  /** Normalize to E.164 (+…) for the given country, or null if invalid. */
  function normalizePhoneForCountry(raw, countryCodeOrName) {
    const country = resolveCountry(countryCodeOrName);
    if (!country) return null;
    let p = String(raw || '').trim().replace(/[\s\-()]/g, '');
    if (!p) return null;
    if (p.startsWith('00')) p = '+' + p.slice(2);
    if (p.startsWith('+')) p = p.slice(1);
    p = p.replace(/\D/g, '');

    const dial = country.dial;
    // Strip leading 0 of local national format
    if (p.startsWith('0')) p = p.slice(1);
    if (p.startsWith(dial)) {
      // already has country dial
    } else {
      p = dial + p;
    }

    // Basic length: dial + at least 6 subscriber digits, max 15 total E.164
    if (p.length < dial.length + 6 || p.length > 15) return null;
    if (!p.startsWith(dial)) return null;
    return '+' + p;
  }

  function isValidPhoneForCountry(raw, countryCodeOrName) {
    return !!normalizePhoneForCountry(raw, countryCodeOrName);
  }

  function optionsHtml(selected) {
    const sel = String(selected || '').toUpperCase();
    return (
      '<option value="">Select country</option>' +
      COUNTRIES.map((c) => {
        const picked = c.code === sel || c.name === selected ? ' selected' : '';
        return `<option value="${c.code}"${picked}>${c.name} (+${c.dial})</option>`;
      }).join('')
    );
  }

  return {
    COUNTRIES,
    findByCode,
    findByName,
    resolveCountry,
    normalizePhoneForCountry,
    isValidPhoneForCountry,
    optionsHtml,
  };
});
