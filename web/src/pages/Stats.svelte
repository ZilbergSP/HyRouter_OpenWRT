<script lang="ts">
  import { onMount } from 'svelte';
  import { api, errorText } from '../lib/api';
  import { count, size } from '../lib/format';
  import type { StateView, StatsReport, StatsRow } from '../lib/types';

  let { view, onstate }: { view: StateView; onstate: (v: StateView) => void } = $props();

  const periods = [
    { id: 'today', name: 'Сегодня' },
    { id: 'yesterday', name: 'Вчера' },
    { id: '7d', name: '7 дней' },
    { id: '30d', name: '30 дней' },
  ];

  let period = $state('today');
  let rep = $state<StatsReport | null>(null);
  let error = $state('');
  let busy = $state(false);

  async function load() {
    try {
      rep = await api.stats(period);
      error = '';
    } catch (e) {
      error = errorText(e);
    }
  }

  onMount(() => {
    load();
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  });

  async function pick(p: string) {
    period = p;
    await load();
  }

  async function toggle(on: boolean) {
    busy = true;
    try {
      onstate((await api.setStats(on)).state);
      await load();
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  async function reset() {
    if (!confirm('Удалить всю собранную статистику?')) return;
    busy = true;
    try {
      await api.resetStats();
      await load();
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  function vpn(r: StatsRow): number {
    return (r.tu ?? 0) + (r.td ?? 0);
  }

  function sorted(rows: StatsRow[] | null | undefined): StatsRow[] {
    return [...(rows ?? [])].sort((a, b) => vpn(b) + (b.du ?? 0) - (vpn(a) + (a.du ?? 0)));
  }

  const maxDay = $derived(Math.max(1, ...(rep?.days ?? []).map((d) => (d.tu ?? 0) + (d.td ?? 0) + (d.du ?? 0))));
</script>

<h1>Статистика</h1>
<p class="lead">
  Трафик и соединения по устройствам, серверам и группам. Какие сайты открывались, HyRouter не записывает.
</p>

<div class="card row">
  {#each periods as p (p.id)}
    <button class:primary={period === p.id} onclick={() => pick(p.id)}>{p.name}</button>
  {/each}
  {#each rep?.months?.slice(0, 3) ?? [] as m (m)}
    <button class:primary={period === m} onclick={() => pick(m)}>{m}</button>
  {/each}
  <span class="spacer"></span>
  <label class="check small">
    <input type="checkbox" checked={view.settings.stats} disabled={busy} onchange={(e) => toggle(e.currentTarget.checked)} /> Собирать
  </label>
  <button class="link danger" disabled={busy} onclick={reset}>Очистить</button>
</div>

{#if error}<div class="notice bad">{error}</div>{/if}
{#if rep?.storeError}<div class="notice bad">{rep.storeError}</div>{/if}

{#if rep}
  <div class="tiles">
    <div class="card tile">
      <div class="muted small">Через VPN</div>
      <div class="big">{size((rep.total.tu ?? 0) + (rep.total.td ?? 0))}</div>
      <div class="muted small">↑ {size(rep.total.tu ?? 0)} ↓ {size(rep.total.td ?? 0)}</div>
    </div>
    <div class="card tile">
      <div class="muted small">Напрямую, отправлено</div>
      <div class="big">{size(rep.total.du ?? 0)}</div>
    </div>
    <div class="card tile">
      <div class="muted small">Соединений</div>
      <div class="big">{count((rep.total.tc ?? 0) + (rep.total.dc ?? 0))}</div>
      <div class="muted small">заблокировано {count(rep.total.bc ?? 0)}, не открылось {count(rep.total.f ?? 0)}</div>
    </div>
  </div>

  {#if rep.days.length > 1}
    <div class="card">
      <h2>По дням</h2>
      <div class="days">
        {#each rep.days as d (d.day)}
          <div class="day" title="{d.day}: VPN {size((d.tu ?? 0) + (d.td ?? 0))}, напрямую {size(d.du ?? 0)}">
            <span class="bar vpn" style="height: {(((d.tu ?? 0) + (d.td ?? 0)) / maxDay) * 100}%"></span>
            <span class="bar direct" style="height: {((d.du ?? 0) / maxDay) * 100}%"></span>
          </div>
        {/each}
      </div>
      <div class="muted small">{rep.from} — {rep.to}</div>
    </div>
  {/if}

  {#each [{ title: 'Устройства', rows: rep.apps }, { title: 'Серверы', rows: rep.servers }, { title: 'Группы', rows: rep.groups }] as part (part.title)}
    {#if (part.rows ?? []).length > 0}
      <div class="card">
        <h2>{part.title}</h2>
        <table>
          <thead><tr><th></th><th class="num">VPN ↑</th><th class="num">VPN ↓</th><th class="num">Напрямую ↑</th><th class="num">Соединений</th></tr></thead>
          <tbody>
            {#each sorted(part.rows) as r (r.k)}
              <tr class:gone={r.gone}>
                <td>{r.n || r.k}{r.gone ? ' (удалён)' : ''}</td>
                <td class="num">{size(r.tu ?? 0)}</td>
                <td class="num">{size(r.td ?? 0)}</td>
                <td class="num">{size(r.du ?? 0)}</td>
                <td class="num">{count((r.tc ?? 0) + (r.dc ?? 0))}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  {/each}
{/if}

<style>
  .tiles {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 12px;
  }
  .tile .big {
    font-size: 1.5rem;
    font-weight: 700;
    margin: 4px 0;
  }
  .days {
    display: flex;
    align-items: flex-end;
    gap: 3px;
    height: 120px;
    margin-bottom: 6px;
  }
  .day {
    flex: 1;
    display: flex;
    align-items: flex-end;
    gap: 1px;
    height: 100%;
  }
  .bar {
    flex: 1;
    border-radius: 2px 2px 0 0;
    min-height: 1px;
  }
  .bar.vpn {
    background: var(--accent);
  }
  .bar.direct {
    background: var(--ok);
  }
  table {
    width: 100%;
    border-collapse: collapse;
  }
  th,
  td {
    text-align: left;
    padding: 5px 8px;
    border-bottom: 1px solid var(--line);
  }
  th {
    font-size: 0.82rem;
    color: var(--muted);
  }
  .num {
    text-align: right;
    white-space: nowrap;
  }
  tr.gone {
    opacity: 0.6;
  }
  @media (max-width: 640px) {
    .tiles {
      grid-template-columns: 1fr;
    }
  }
</style>
