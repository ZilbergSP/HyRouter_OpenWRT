// Ready-made rules and schemes, from HyRoute's frontend/src/lib/templates.ts
// (e1c4466). Services use lists from the rule database (geosite:/geoip:),
// which are maintained upstream and updated by HyRouter, so a template
// never goes stale when a service adds a new CDN domain.
//
// On the router a rule names devices, not programs: the router's DNS sees
// the names every device and app looks up, so one site template covers the
// app too and HyRoute's «программа» templates have no counterpart. HyRoute's
// «Локальная сеть» (geoip:private → direct) is left out: HyRouter never
// intercepts local and private addresses (skip4/skip6 of the compilers).
import type { Action, GeoStatus, Rule, RulesConfig } from './types';

export interface Template {
  id: string;
  name: string;
  hint: string;
  domains: string[];
  action?: Action; // default: tunnel
  group: Group;
}

export type Group = 'Россия' | 'Сервисы' | 'Полезное';
export const tplGroups: Group[] = ['Россия', 'Сервисы', 'Полезное'];

export const templates: Template[] = [
  {
    id: 'ru-blocked',
    name: 'Заблокированное в России',
    hint: 'сайты и IP из реестра блокировок → VPN',
    domains: ['geosite:ru-blocked', 'geoip:ru-blocked'],
    group: 'Россия',
  },
  {
    id: 'ru-inside',
    name: 'Работает только из России',
    hint: 'Госуслуги, банки и т. п. → напрямую',
    domains: ['geosite:ru-available-only-inside', 'geosite:category-gov-ru', 'geosite:category-bank-ru'],
    action: 'direct',
    group: 'Россия',
  },
  {
    id: 'ru-all',
    name: 'Российские сайты и IP',
    hint: 'зона .ru, Яндекс, VK, российские сети → напрямую',
    domains: ['geosite:category-ru', 'geoip:ru'],
    action: 'direct',
    group: 'Россия',
  },

  { id: 'youtube', name: 'YouTube', hint: 'сайт, видео, превью, приложение', domains: ['geosite:youtube'], group: 'Сервисы' },
  { id: 'discord', name: 'Discord', hint: 'сайт, приложение, голосовые серверы', domains: ['geosite:discord'], group: 'Сервисы' },
  { id: 'telegram', name: 'Telegram', hint: 'приложение и веб-версия: сайты и IP-адреса Telegram', domains: ['geosite:telegram', 'geoip:telegram'], group: 'Сервисы' },
  { id: 'chatgpt', name: 'ChatGPT', hint: 'chatgpt.com, OpenAI и приложение', domains: ['geosite:openai'], group: 'Сервисы' },
  { id: 'claude', name: 'Claude', hint: 'claude.ai, Anthropic и приложение', domains: ['geosite:anthropic'], group: 'Сервисы' },
  { id: 'ai', name: 'Все ИИ-сервисы', hint: 'ChatGPT, Claude, Gemini, Copilot…', domains: ['geosite:category-ai-!cn'], group: 'Сервисы' },
  { id: 'instagram', name: 'Instagram', hint: 'сайт, медиа и приложение', domains: ['geosite:instagram'], group: 'Сервисы' },
  { id: 'meta', name: 'Facebook, Instagram, WhatsApp', hint: 'все сервисы Meta', domains: ['geosite:meta'], group: 'Сервисы' },
  { id: 'x', name: 'X (Twitter)', hint: 'x.com, медиа и приложение', domains: ['geosite:twitter'], group: 'Сервисы' },
  { id: 'spotify', name: 'Spotify', hint: 'сайт и приложение', domains: ['geosite:spotify'], group: 'Сервисы' },
  { id: 'netflix', name: 'Netflix', hint: 'сайт и видео', domains: ['geosite:netflix'], group: 'Сервисы' },
  { id: 'twitch', name: 'Twitch', hint: 'сайт и трансляции', domains: ['geosite:twitch'], group: 'Сервисы' },
  { id: 'linkedin', name: 'LinkedIn', hint: 'сайт и медиа', domains: ['geosite:linkedin'], group: 'Сервисы' },

  { id: 'ads', name: 'Реклама', hint: 'рекламные сети → блок', domains: ['geosite:category-ads-all'], action: 'block', group: 'Полезное' },
  { id: 'telemetry', name: 'Телеметрия Windows', hint: 'сбор данных Microsoft с компьютеров на Windows → блок', domains: ['geosite:win-spy'], action: 'block', group: 'Полезное' },
];

// ruleFromTemplate is a new rule for every device of the LAN; the editor
// lets the user pick devices and a server before it is added.
export function ruleFromTemplate(t: Template): Rule {
  return { name: t.name, domains: [...t.domains], action: t.action ?? 'tunnel' };
}

// A scheme is a whole setup: several rules plus "everything else".
export interface Scheme {
  id: string;
  name: string;
  hint: string;
  rules: (string | Template)[]; // template IDs or inline rules, top to bottom
  rest: Action;
  source?: string; // the rule database the scheme is made for
}

export const schemes: Scheme[] = [
  {
    id: 'ru-blocked-only',
    name: 'Через VPN только заблокированное',
    hint: 'Всё, что заблокировано в России, — через VPN, остальное напрямую. Быстро и экономит трафик.',
    rules: ['ru-inside', 'ru-blocked'],
    rest: 'direct',
  },
  {
    id: 'all-but-ru',
    name: 'Всё через VPN, кроме российского',
    hint: 'Российские сайты, банки и Госуслуги — напрямую, всё остальное — через VPN.',
    rules: ['ru-inside', 'ru-all'],
    rest: 'tunnel',
  },
  {
    // hydraponique/roscomvpn-routing, DEFAULT: block, then proxy, then
    // direct, everything else through the VPN. Torrents go direct instead
    // of being blocked: a block would break the torrent clients of the LAN,
    // and direct keeps them off the VPN server just the same.
    id: 'roscomvpn',
    name: 'RoscomVPN',
    hint: 'Маршрутизация RoscomVPN: реклама и телеметрия — блок; YouTube, Telegram, GitHub, Google Play — через VPN; российское, Microsoft, Apple, игры и торренты — напрямую; остальное — через VPN.',
    source: 'hysteria-geodata',
    rules: [
      { id: 'rc-block', name: 'Реклама и телеметрия', hint: '', domains: ['geosite:win-spy', 'geosite:category-ads-all'], action: 'block', group: 'Полезное' },
      { id: 'rc-proxy', name: 'Через VPN (RoscomVPN)', hint: '', domains: ['geosite:google-play', 'geosite:github', 'geosite:twitch-ads', 'geosite:youtube', 'geosite:telegram'], group: 'Сервисы' },
      {
        id: 'rc-direct',
        name: 'Напрямую (RoscomVPN)',
        hint: '',
        domains: [
          'geosite:whitelist', 'geosite:category-ru', 'geoip:direct', 'geosite:microsoft', 'geosite:apple', 'geosite:epicgames', 'geosite:riot',
          'geosite:escapefromtarkov', 'geosite:steam', 'geosite:twitch', 'geosite:pinterest', 'geosite:faceit', 'geosite:torrent',
        ],
        action: 'direct',
        group: 'Россия',
      },
    ],
    rest: 'tunnel',
  },
];

export function schemeTemplates(sc: Scheme): Template[] {
  return sc.rules.map((r) => (typeof r === 'string' ? templates.find((t) => t.id === r)! : r));
}

// applyScheme puts the scheme's rules on top and sets "everything else".
// Rules are checked top to bottom, and lists overlap by content, not by
// name (geosite:microsoft holds github.com, category-ru holds ad domains),
// so a scheme works only as a whole and in its own order. It counts as
// applied, and nothing is added, only when all its rules are there in that
// order, each working the same way (enabled, for every device, protocol
// and port) and with no enabled rule of another action above it but the
// scheme's own: such a rule may send some of the same traffic elsewhere
// (*.ru or geosite:yandex above category-ru), which list names cannot
// tell. Otherwise the whole scheme goes on top; old copies below stay as
// they are.
export function applyScheme(c: RulesConfig, sc: Scheme): RulesConfig {
  const next: RulesConfig = JSON.parse(JSON.stringify(c));
  next.rules = next.rules ?? [];
  const key = (r: Rule) => JSON.stringify([...(r.domains ?? [])].sort()) + r.action;
  const general = (r: Rule) => r.enabled !== false && !r.devices?.length && !r.protocol && !r.ports;
  const want = schemeTemplates(sc).map(ruleFromTemplate);
  // The earliest copy of each rule after the previous one's: the fewest
  // rules above it and the most room for the rest.
  const own = new Set<number>();
  let from = 0;
  const applied = want.every((r) => {
    const i = next.rules.findIndex((x, j) => j >= from && general(x) && key(x) === key(r));
    if (i < 0 || next.rules.slice(0, i).some((a, j) => !own.has(j) && a.enabled !== false && a.action !== r.action)) return false;
    own.add(i);
    from = i + 1;
    return true;
  });
  if (!applied) next.rules = [...want, ...next.rules];
  next.defaultAction = sc.rest;
  return next;
}

// sourceName is a rule database's short name.
export function sourceName(geo: GeoStatus, id: string): string {
  return geo.sources.find((s) => s.id === id)?.short ?? id;
}

// missingLists explains the first well-known list of domains that the
// database in use lacks ('' when it has them all, or it is not known yet).
// Lists HyRouter does not describe count as present.
export function missingLists(domains: string[], geo: GeoStatus | null): string {
  if (!geo) return '';
  for (const d of domains) {
    const m = /^geo(site|ip):(.+)$/i.exec(d);
    if (!m) continue;
    const kind = m[1].toLowerCase();
    const c = geo.categories.find((x) => x.kind === kind && x.name === m[2].toLowerCase());
    if (c && !c.sources.includes(geo.source)) {
      return `${d} нет в базе ${sourceName(geo, geo.source)}, есть в: ${c.sources.map((s) => sourceName(geo, s)).join(', ')}`;
    }
  }
  return '';
}
