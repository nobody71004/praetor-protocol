const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const PRAETOR_PROTOCOL = 'PRAETOR/1';
const PRAETOR_SUITES = new Set(['PSEAL', 'FAST', 'BOLT', 'PMARINE']);
const PRAETOR_CELL_SIZES = new Set([512, 1024, 2048, 4096]);
const PRAETOR_ENDPOINT = '104.251.218.227:9443';
const PRAETOR_SERVER_PUBLIC_KEY = '46VZiVJjOhoFKyU6DcQfBblmh9ch/5in3/B2EAwtmCLBw9dg1xsl6dMdL7J2C7UiivO4mVmSxAeaBRQVTKw3JsWaURiKPIGI6KREJCc3Q0sR2yBrimdPw8LKyjoYHwiVRDKOI9k9i4itUgEGmlezw1yeapG5ZsEjGqxei3bMXTG/ZarF/zFDn6ed4rxy4OuRc5ZwwEEPrZDANmctg8IB+gce7QuPmlEt6WJCh+KATZtq64YRLSx4iopx2+oKlkpIKmxkSdSthbWCyYoZ8eWIOxIg00hax+E4gxNMVsOs/GSvEmRJzFuceQd7tQhW9qsIM6AlpKG9dxyupCk2c3Z2/RZ2qvpOS3AWtTKKBAVQ3TA3f+QI3pNOFBAuKgQEajEEwyegb9zLbwIqJ3hCn6cM16oZ7wJw4aZPsgWsqnpR6FVvYxUdEqAplkae1soMEySPzxELqTIxtLNvJ0ktn1VbEjg5LqUJRmU5Hjpz36YlxWRJ/dubikm4vMixpEZf4yRJpZxHwfAbWrOSrMRjbGnE7gg5q2EHE7F6aoUFv8yIkni3UDMDBFgVojpbnop7LbiDvTuo5MGi4nec9LMIGJs9lSu9QiSF52wVH/qZW/BJtApsGgyA7CikGPC6FuNxFum3rNKAByMs6Ehc0bsE+tjJNVeYSoAx1TLJQVdH5OI8VoqaYgTLzjCfMdaEHUWvpdhWErg8sXSh96UIX8vOjmGkyyII5WCs5okOAgqN3gU/wjGsZqcevcCpYgJ7q7KBGlFBKrGkwSuAKSWCskEs9zgUb3eURKFqLYxDtvGYtXQSSCzGQeBduShHOteTf6w9m7YHlJJsDNdGCnMXdoutD3Ccn9aaaKiDO5sf75kn6LlNjHBimmS0NqhedhOmIwN3gvWCh0uJFFgLOyQtSEVC0FGwdvOU/5IeY1m72LQ1K9AgGXagJYDJ4VFjlQeou8nFoTLE67mgzQqvgQx+g6fMzLZn23CvlZN5TRdPYkS/70jM0Yw6YvB3tlcn+oOKL3fG7HZvV+rNtTl9JGca+ai2xqK58PmUcECpEPVwLqVgxXGTKUK2iJwLR6a8B5Yii+KiaBVochqpYCkywBZHL/tjfkZAppG9VYNcjtNw6oACwbYoPPZFWURTYAaCkigd4+BHq8K+RIUhtiUH6vSsaGR4jsIGukk9kCDP2ROoHAaBPvYalNqVu8uBPVM6vBiPsgRCYBsRvgES79JyWrtFJDad21OvyFvINJAT5wK73fpmPkyfRiOrO9cw9soeU2UGBpGHpiNQ3NgxOSNgIogUTInDEwqkzGRTd6O1YwsZUzl/kXqsxLBcWUZ4SIoBtPVcRuhMxeIQelkLqRW8tBXPw3QQ7lKvE/pXJpgZG9JRW5NFyTQMYsEK9GOaahoDfkN279CR1binU5pfMZhtxgZGjxDCDesMGcao7kV6B/iTUcJcRBZmkBpoTZeUxYhenSdmBtFXWfaFM2S41zt8yohKQgGGXMFsbAQ4ntmmWnabu/l05Le/UuEXnQVxJkSlFUddP+kz8Qym2KucywV4d9vn3sAJ1w0KYpGOLiwV5ghXIYUVGNW3pOShU/oLqDmUz+eRRuXZRzthg9qr83vp9oQ0Kz2z0DFkCw==';
const PROFILE_COLORS = new Set(['mint', 'violet', 'amber', 'ice']);

function validServerKey(value) {
  const text = String(value || '').replace(/\s+/g, '');
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(text)) return false;
  try {
    return Buffer.from(text, 'base64').length === 1216;
  } catch {
    return false;
  }
}

function normalizeEndpoint(value) {
  let endpoint = String(value || '').trim();
  if (!endpoint) return PRAETOR_ENDPOINT;
  endpoint = endpoint.replace(/:51820$/, ':9443');
  if (!/:\d{1,5}$/.test(endpoint)) endpoint = `${endpoint}:9443`;
  return endpoint;
}

function makeProfile(overrides = {}) {
  const now = new Date().toISOString();
  const cellSize = Number(overrides.cellSize);
  const tags = Array.isArray(overrides.tags)
    ? [...new Set(overrides.tags.map((tag) => String(tag).trim()).filter(Boolean))].slice(0, 8)
    : [];
  return {
    id: overrides.id || crypto.randomUUID(),
    name: String(overrides.name || 'New PRAETOR profile').slice(0, 80),
    description: String(overrides.description || 'A pinned PRAETOR/1 crypto profile.').slice(0, 300),
    location: String(overrides.location || 'Local').slice(0, 80),
    endpoint: normalizeEndpoint(overrides.endpoint),
    protocol: PRAETOR_PROTOCOL,
    suite: PRAETOR_SUITES.has(overrides.suite) ? overrides.suite : 'PSEAL',
    transport: 'tcp',
    cellSize: PRAETOR_CELL_SIZES.has(cellSize) ? cellSize : 1024,
    serverPublicKey: validServerKey(overrides.serverPublicKey)
      ? String(overrides.serverPublicKey).replace(/\s+/g, '')
      : PRAETOR_SERVER_PUBLIC_KEY,
    autoConnect: Boolean(overrides.autoConnect),
    tags,
    color: PROFILE_COLORS.has(overrides.color) ? overrides.color : 'mint',
    createdAt: overrides.createdAt || now,
    updatedAt: overrides.updatedAt || now,
  };
}

function defaultProfiles() {
  return [
    makeProfile({
      id: 'seed-praetor-pseal',
      name: 'Nexus PSEAL',
      description: 'Default PRAETOR/1 profile: SIV + commitment record protection over a pinned hybrid X-Wing handshake.',
      location: 'Dallas, TX',
      endpoint: PRAETOR_ENDPOINT,
      suite: 'PSEAL',
      cellSize: 1024,
      autoConnect: true,
      tags: ['pq', 'siv', 'default'],
      color: 'mint',
    }),
    makeProfile({
      id: 'seed-praetor-fast',
      name: 'Nexus FAST',
      description: 'Routing profile for throughput-sensitive sessions; the current egress negotiates PSEAL.',
      location: 'Dallas, TX',
      endpoint: PRAETOR_ENDPOINT,
      suite: 'FAST',
      cellSize: 1024,
      tags: ['pq', 'aes-gcm', 'opt-in'],
      color: 'violet',
    }),
    makeProfile({
      id: 'seed-praetor-bolt',
      name: 'Nexus BOLT',
      description: 'Routing profile for lower per-cell cost; the current egress negotiates PSEAL.',
      location: 'Dallas, TX',
      endpoint: PRAETOR_ENDPOINT,
      suite: 'BOLT',
      cellSize: 1024,
      tags: ['pq', 'aegis', 'opt-in'],
      color: 'amber',
    }),
    makeProfile({
      id: 'seed-praetor-pmarine',
      name: 'Nexus PMARINE',
      description: 'Experimental PMARINE (PSEAL/2) preset over AEGIS-256; the current egress negotiates PSEAL.',
      location: 'Dallas, TX',
      endpoint: PRAETOR_ENDPOINT,
      suite: 'PMARINE',
      cellSize: 1024,
      tags: ['pq', 'aegis-256', 'experimental'],
      color: 'ice',
    }),
  ];
}

const DEFAULT_SETTINGS = Object.freeze({
  accent: 'mint',
  animations: true,
  cursorEffects: true,
  glass: 72,
  autoConnect: false,
  launchAtLogin: false,
  killSwitch: true,
  dnsLeakProtection: true,
  allowLan: false,
  mcpFullControl: false,
  mcpAllowedRoots: [],
  agentModel: 'gpt-4o-mini',
  agentBaseUrl: 'https://api.openai.com/v1',
  heroTitle: 'Network control, without the friction.',
  headerCaption: 'PRAETOR / CONTROL PLANE 01',
});

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

class Store {
  constructor(userData) {
    this.userData = userData;
    this.file = path.join(userData, 'state.json');
    this.data = this.load();
  }

  load() {
    fs.mkdirSync(this.userData, { recursive: true });
    let saved = null;
    try {
      saved = JSON.parse(fs.readFileSync(this.file, 'utf8'));
    } catch {
      saved = null;
    }

    const defaults = {
      schemaVersion: 4,
      settings: {
        ...DEFAULT_SETTINGS,
        mcpAllowedRoots: [process.env.PRAETOR_DEFAULT_ROOT || require('node:os').homedir()],
      },
      profiles: defaultProfiles(),
      activity: [],
    };

    if (!saved || typeof saved !== 'object') {
      const initial = defaults;
      initial.activity = [
        {
          id: crypto.randomUUID(),
          kind: 'system',
          title: 'PRAETOR profile store initialized',
          detail: 'Four PRAETOR/1 crypto profiles seeded against the Dallas egress service (104.251.218.227:9443).',
          ts: Date.now(),
        },
      ];
      this.data = initial;
      this.save();
      return initial;
    }

    const rawProfiles = Array.isArray(saved.profiles) ? saved.profiles : [];
    const hasPraetorProfiles = rawProfiles.some(
      (profile) => profile?.protocol === PRAETOR_PROTOCOL && PRAETOR_SUITES.has(profile?.suite),
    );

    if (rawProfiles.length && !hasPraetorProfiles) {
      try {
        fs.copyFileSync(this.file, `${this.file}.v1-wireguard-backup`);
      } catch {
        // The legacy backup is best-effort; migration still proceeds.
      }
    }

    let profiles = !rawProfiles.length || !hasPraetorProfiles
      ? defaults.profiles
      : rawProfiles.filter((profile) => profile?.protocol === PRAETOR_PROTOCOL).map((profile) => makeProfile(profile));

    let migratedToEgress = false;
    if ((Number(saved.schemaVersion) || 1) < 3) {
      profiles = profiles.map((profile) => {
        if (!String(profile?.id || '').startsWith('seed-praetor-')) return profile;
        migratedToEgress = true;
        return makeProfile({
          ...profile,
          endpoint: PRAETOR_ENDPOINT,
          location: 'Dallas, TX',
          serverPublicKey: PRAETOR_SERVER_PUBLIC_KEY,
        });
      });
    }

    // Add the PMARINE preset when upgrading a profile store created before it
    // shipped. A user who deletes it later keeps it deleted because this only
    // runs while the saved schema is older than 4.
    let addedPmarine = false;
    if (
      (Number(saved.schemaVersion) || 1) < 4
      && !profiles.some((profile) => profile.id === 'seed-praetor-pmarine')
    ) {
      const pmarine = defaults.profiles.find((profile) => profile.id === 'seed-praetor-pmarine');
      if (pmarine) {
        profiles = [...profiles, pmarine];
        addedPmarine = true;
      }
    }

    const settings = { ...defaults.settings, ...(saved.settings || {}) };
    if (!Array.isArray(settings.mcpAllowedRoots) || settings.mcpAllowedRoots.length === 0) {
      settings.mcpAllowedRoots = defaults.settings.mcpAllowedRoots;
    }

    let activity = Array.isArray(saved.activity) ? saved.activity.slice(0, 300) : [];
    if (rawProfiles.length && !hasPraetorProfiles) {
      activity = [
        {
          id: crypto.randomUUID(),
          kind: 'system',
          title: 'PRAETOR profiles migrated',
          detail: 'WireGuard-shaped sample profiles were replaced with PRAETOR/1 crypto profiles. The previous state was backed up.',
          ts: Date.now(),
        },
        ...activity,
      ];
    }

    if (migratedToEgress) {
      activity = [
        {
          id: crypto.randomUUID(),
          kind: 'system',
          title: 'PRAETOR egress enabled',
          detail: 'Seeded profiles now use the Dallas PRAETOR/1 egress service at 104.251.218.227:9443.',
          ts: Date.now(),
        },
        ...activity,
      ];
    }

    if (addedPmarine) {
      activity = [
        {
          id: crypto.randomUUID(),
          kind: 'system',
          title: 'PMARINE profile added',
          detail: 'Nexus PMARINE is available as an experimental preset. The current egress still negotiates PSEAL.',
          ts: Date.now(),
        },
        ...activity,
      ];
    }

    this.data = {
      schemaVersion: 4,
      settings,
      profiles,
      activity,
    };
    if (addedPmarine || migratedToEgress) this.save();
    return this.data;
  }

  save() {
    fs.mkdirSync(this.userData, { recursive: true });
    const temporary = `${this.file}.tmp`;
    fs.writeFileSync(temporary, JSON.stringify(this.data, null, 2), 'utf8');
    fs.renameSync(temporary, this.file);
  }

  getSettings() {
    return clone(this.data.settings);
  }

  saveSettings(patch) {
    if (!patch || typeof patch !== 'object') return this.getSettings();
    const next = { ...this.data.settings };
    for (const keyName of Object.keys(DEFAULT_SETTINGS)) {
      if (Object.prototype.hasOwnProperty.call(patch, keyName)) {
        next[keyName] = patch[keyName];
      }
    }
    next.accent = ['mint', 'violet', 'amber', 'ice'].includes(next.accent) ? next.accent : 'mint';
    next.glass = Math.max(20, Math.min(100, Number(next.glass) || 72));
    next.mcpAllowedRoots = Array.isArray(next.mcpAllowedRoots)
      ? [...new Set(next.mcpAllowedRoots.filter((entry) => typeof entry === 'string' && entry.trim()).map((entry) => path.resolve(entry)))]
      : this.data.settings.mcpAllowedRoots;
    if (!next.mcpAllowedRoots.length) next.mcpAllowedRoots = this.data.settings.mcpAllowedRoots;
    next.agentModel = String(next.agentModel || 'gpt-4o-mini').slice(0, 80);
    next.agentBaseUrl = String(next.agentBaseUrl || 'https://api.openai.com/v1').replace(/\/+$/, '');
    next.heroTitle = String(next.heroTitle || DEFAULT_SETTINGS.heroTitle).slice(0, 180);
    next.headerCaption = String(next.headerCaption || DEFAULT_SETTINGS.headerCaption).slice(0, 80);
    this.data.settings = next;
    this.save();
    return this.getSettings();
  }

  listProfiles() {
    return clone(this.data.profiles);
  }

  getProfile(id) {
    const profile = this.data.profiles.find((entry) => entry.id === id);
    return profile ? clone(profile) : null;
  }

  saveProfile(input) {
    if (!input || typeof input !== 'object') throw new Error('Profile payload is required.');
    const existing = input.id ? this.data.profiles.find((entry) => entry.id === input.id) : null;
    if (existing) {
      const merged = makeProfile({
        ...existing,
        ...input,
        id: existing.id,
        createdAt: existing.createdAt,
        updatedAt: new Date().toISOString(),
      });
      this.data.profiles = this.data.profiles.map((entry) => (entry.id === existing.id ? merged : entry));
      this.save();
      return clone(merged);
    }
    const created = makeProfile({
      ...input,
      id: crypto.randomUUID(),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });
    this.data.profiles.unshift(created);
    this.save();
    return clone(created);
  }

  deleteProfile(id) {
    const before = this.data.profiles.length;
    this.data.profiles = this.data.profiles.filter((entry) => entry.id !== id);
    if (this.data.profiles.length === before) return false;
    this.save();
    return true;
  }

  logActivity(kind, title, detail = '', meta = {}) {
    const entry = {
      id: crypto.randomUUID(),
      kind: String(kind || 'system'),
      title: String(title || 'Event'),
      detail: String(detail || ''),
      meta,
      ts: Date.now(),
    };
    this.data.activity.unshift(entry);
    this.data.activity = this.data.activity.slice(0, 300);
    this.save();
    return clone(entry);
  }

  listActivity() {
    return clone(this.data.activity);
  }

  clearActivity() {
    this.data.activity = [];
    this.save();
  }
}

module.exports = { Store, DEFAULT_SETTINGS };
