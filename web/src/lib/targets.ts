// Names of the routing targets: servers and server groups.

import type { StateView } from './types';

export function isGroup(id: string): boolean {
  return id.startsWith('grp-');
}

export function targetName(view: StateView, id: string): string {
  const s = view.servers.find((x) => x.id === id);
  if (s) return s.name;
  const g = view.groups.groups.find((x) => x.id === id);
  if (g) return `группа «${g.name}»`;
  return isGroup(id) ? 'удалённая группа' : 'удалённый сервер';
}

export function mainName(view: StateView): string {
  return view.settings.main ? targetName(view, view.settings.main) : 'не выбран';
}

// The servers a group can list one by one: those added by hand (a
// subscription's servers join a group through the subscription).
export function ownServers(view: StateView) {
  return view.servers.filter((s) => !s.source);
}

// plural picks the Russian form for n: (1) сервер, (2) сервера, (5) серверов.
export function plural(n: number, one: string, few: string, many: string): string {
  const m10 = n % 10;
  const m100 = n % 100;
  if (m10 === 1 && m100 !== 11) return one;
  if (m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14)) return few;
  return many;
}
