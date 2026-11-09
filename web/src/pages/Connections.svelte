<script lang="ts">
  import { onMount } from 'svelte';
  import { api, errorText } from '../lib/api';
  import { size } from '../lib/format';
  import { targetName } from '../lib/targets';
  import type { ConnView, StateView } from '../lib/types';

  let { view }: { view: StateView } = $props();

  let active = $state<ConnView[]>([]);
  let closed = $state<ConnView[]>([]);
  let error = $state('');
  let showClosed = $state(false);
  let route = $state('');
  let device = $state('');
  let query = $state('');
  let paused = $state(false);

  const routeText: Record<string, string> = { tunnel: 'VPN', direct: 'напрямую', block: 'блок' };

  async function load() {
    try {
      const r = await api.connections();
      active = r.active;
      closed = r.closed;
      error = '';
    } catch (e) {
      error = errorText(e);
    }
  }

  onMount(() => {
    load();
    const t = setInterval(() => {
      if (!paused) load();
    }, 2000);
    return () => clearInterval(t);
  });

  const rows = $derived(
    (showClosed ? closed : [...active].sort((a, b) => b.start.localeCompare(a.start))).filter(
      (c) =>
        (!route || c.route === route) &&
        (!device || c.path === device) &&
        (!query || `${c.domain} ${c.dst} ${c.process} ${c.rule}`.toLowerCase().includes(query.toLowerCase())),
    ),
  );

  const devices = $derived(
    [...new Map([...active, ...closed].map((c) => [c.path, c.process])).entries()].sort((a, b) => a[1].localeCompare(b[1])),
  );

  function server(c: ConnView): string {
    if (c.route !== 'tunnel' || !c.profile) return '';
    const s = targetName(view, c.profile);
    return c.group ? `${s} (${targetName(view, c.group)})` : s;
  }

  function outcome(c: ConnView): string {
    if (!c.outcome || c.outcome === 'passed') return '';
    return c.outcome.replace(/^(rst|dropped): /, '');
  }
</script>

<h1>Соединения</h1>
<p class="lead">
  Соединения устройств сети, которые решил HyRouter: куда идут, по какому правилу и через какой сервер. Список живой и нигде
  не сохраняется.
</p>

<div class="card filters">
  <div class="row">
    <select class="auto" bind:value={route}>
      <option value="">Все маршруты</option>
      <option value="tunnel">Через VPN</option>
      <option value="direct">Напрямую</option>
      <option value="block">Заблокированные</option>
    </select>
    <select class="auto" bind:value={device}>
      <option value="">Все устройства</option>
      {#each devices as [key, name] (key)}<option value={key}>{name}</option>{/each}
    </select>
    <input class="grow" bind:value={query} placeholder="Поиск: сайт, адрес, правило" />
  </div>
  <div class="row">
    <label class="check small"><input type="checkbox" bind:checked={showClosed} /> Закрытые</label>
    <label class="check small"><input type="checkbox" bind:checked={paused} /> Пауза</label>
    <span class="spacer"></span>
    <span class="muted small">Открыто: {active.length}</span>
  </div>
</div>

{#if error}<div class="notice bad">{error}</div>{/if}

<div class="card table">
  {#if rows.length === 0}
    <p class="muted">Соединений нет.</p>
  {:else}
    <table>
      <thead>
        <tr><th>Устройство</th><th>Куда</th><th>Маршрут</th><th>Правило</th><th class="num">↑</th><th class="num">↓</th></tr>
      </thead>
      <tbody>
        {#each rows.slice(0, 500) as c (c.id)}
          <tr>
            <td>{c.process}</td>
            <td class="dst">
              {#if c.domain}<strong>{c.domain}</strong><br />{/if}
              <span class="muted small">{c.proto} {c.dst}</span>
            </td>
            <td>
              <span class="badge {c.route === 'direct' ? 'ok' : c.route === 'block' ? 'bad' : ''}">{routeText[c.route] ?? c.route}</span>
              {#if server(c)}<div class="small">{server(c)}</div>{/if}
              {#if outcome(c)}<div class="small err">{outcome(c)}</div>{/if}
            </td>
            <td class="small">{c.rule}</td>
            <td class="num small">{size(c.sent)}</td>
            <td class="num small">{c.recv >= 0 ? size(c.recv) : '—'}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

<style>
  .filters {
    display: grid;
    gap: 8px;
  }
  .auto {
    width: auto;
  }
  .grow {
    flex: 1;
    min-width: 160px;
    width: auto;
  }
  .table {
    overflow-x: auto;
  }
  table {
    width: 100%;
    border-collapse: collapse;
  }
  th,
  td {
    text-align: left;
    padding: 6px 8px;
    border-bottom: 1px solid var(--line);
    vertical-align: top;
  }
  th {
    font-size: 0.82rem;
    color: var(--muted);
    font-weight: 600;
  }
  .num {
    text-align: right;
    white-space: nowrap;
  }
  .dst {
    word-break: break-all;
  }
  .err {
    color: var(--bad);
  }
</style>
