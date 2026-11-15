<script lang="ts">
  import { onMount } from 'svelte';
  import { api, errorText } from '../lib/api';
  import type { PingView, Server, StateView, Status } from '../lib/types';
  import { ownServers } from '../lib/targets';
  import Subs from './Subs.svelte';

  let { view, status, onstate }: { view: StateView; status: Status; onstate: (v: StateView) => void } = $props();

  let link = $state('');
  let name = $state('');
  let busy = $state(false);
  let error = $state('');
  let warnings = $state<string[]>([]);
  let renaming = $state('');
  let newName = $state('');

  const stateText: Record<string, string> = {
    stopped: 'не запущен',
    connecting: 'подключается',
    connected: 'подключён',
    failed: 'ошибка',
  };

  function statusOf(id: string) {
    return status.servers.find((s) => s.id === id);
  }

  async function run(f: () => Promise<{ state: StateView }>) {
    busy = true;
    error = '';
    try {
      onstate((await f()).state);
      return true;
    } catch (e) {
      error = errorText(e);
      return false;
    } finally {
      busy = false;
    }
  }

  async function add(e: SubmitEvent) {
    e.preventDefault();
    warnings = [];
    busy = true;
    error = '';
    try {
      const r = await api.addServer(link.trim(), name.trim());
      onstate(r.state);
      warnings = r.warnings;
      link = '';
      name = '';
    } catch (err) {
      error = errorText(err);
    } finally {
      busy = false;
    }
  }

  function startRename(id: string, current: string) {
    renaming = id;
    newName = current;
  }

  async function rename(id: string) {
    if (await run(() => api.renameServer(id, newName.trim()))) renaming = '';
  }

  async function remove(id: string, n: string) {
    if (!confirm(`Удалить сервер «${n}»? Правила, которые на него ссылаются, будут отклонять трафик, пока вы не выберете другой сервер.`)) return;
    await run(() => api.deleteServer(id));
  }

  function protocol(p?: string): string {
    return p === 'vless' ? 'VLESS' : 'Hysteria 2';
  }

  // The list: a search, a filter (all, added by hand, a subscription),
  // the order by ping, a compact view (one line a server; a long list
  // opens compact, the choice is kept in this browser).
  let query = $state('');
  let filter = $state('all');
  let byPing = $state(false);
  let compact = $state(readCompact());
  let pings = $state<PingView | null>(null);

  function readCompact(): boolean {
    try {
      const v = localStorage.getItem('hyrouter.servers.compact');
      if (v !== null) return v === '1';
    } catch {
      // no storage: the default
    }
    return view.servers.length > 15;
  }

  function setCompact(on: boolean) {
    compact = on;
    try {
      localStorage.setItem('hyrouter.servers.compact', on ? '1' : '0');
    } catch {
      // kept for this page only
    }
  }

  function subName(source?: string): string {
    const id = source?.replace(/^sub:/, '');
    return view.subs.find((s) => s.id === id)?.name ?? 'подписка';
  }

  function matches(s: Server, q: string): boolean {
    if (!q) return true;
    const text = [s.name, s.host, s.ports, protocol(s.protocol), s.source ? subName(s.source) : 'вручную'].join(' ').toLowerCase();
    return q
      .toLowerCase()
      .split(/\s+/)
      .every((w) => text.includes(w));
  }

  // pingRank: answered first by delay, then failed, then not measured.
  function pingRank(id: string): number {
    const r = pings?.results[id];
    if (r?.ms) return r.ms;
    return r ? 1e9 : 2e9;
  }

  const shown = $derived.by(() => {
    const list = view.servers.filter(
      (s) => (filter === 'all' || (filter === 'own' ? !s.source : s.source === filter)) && matches(s, query.trim()),
    );
    return byPing ? [...list].sort((a, b) => pingRank(a.id) - pingRank(b.id)) : list;
  });

  const pingRunning = $derived(!!pings?.running);

  async function loadPings() {
    try {
      pings = await api.pings();
    } catch {
      // the list works without
    }
  }

  onMount(() => {
    loadPings();
    const t = setInterval(() => {
      if (pings?.running) loadPings();
    }, 1500);
    return () => clearInterval(t);
  });

  async function ping(ids: string[]) {
    error = '';
    try {
      pings = await api.ping(ids);
    } catch (e) {
      error = errorText(e);
    }
  }

  async function stopPing() {
    try {
      pings = await api.pingStop();
    } catch (e) {
      error = errorText(e);
    }
  }

  function pingText(id: string): string {
    if (pings?.pending.includes(id)) return '…';
    const r = pings?.results[id];
    if (!r) return 'пинг';
    return r.ms ? `${r.ms} мс` : 'нет ответа';
  }
</script>

<h1>Серверы</h1>
<p class="lead">
  Серверы, через которые идёт трафик «через VPN». Основной сервер берут правила без своего сервера. Пароли серверов
  хранятся только на роутере.
</p>

<form class="card" onsubmit={add}>
  <h2>Добавить сервер</h2>
  <label class="field">
    <span>Ссылка {view.vless ? 'hysteria2:// или vless://' : 'hysteria2://'}</span>
    <textarea rows="2" bind:value={link} placeholder={view.vless ? 'hysteria2://… или vless://…' : 'hysteria2://…'} required></textarea>
  </label>
  <label class="field">
    <span>Название (необязательно)</span>
    <input bind:value={name} placeholder="Например, Нидерланды" />
  </label>
  {#if view.lite}
    <p class="muted small">В HyRouter Lite поддерживается только Hysteria 2: VLESS требует ядро Xray, которое не помещается на слабые роутеры.</p>
  {/if}
  <button class="primary" type="submit" disabled={busy || !link.trim()}>Добавить</button>
</form>

{#if error}<div class="notice bad">{error}</div>{/if}
{#if warnings.length > 0}
  <div class="notice">
    Сервер добавлен, но не всё из ссылки перенесено:
    <ul>
      {#each warnings as w, i (i)}<li>{w}</li>{/each}
    </ul>
  </div>
{/if}

<div class="card">
  <h2>Серверы</h2>
  {#if view.servers.length === 0}
    <p class="muted">Серверов пока нет: добавьте сервер по ссылке выше или подписку ниже.</p>
  {:else}
    <div class="row tools">
      <input class="search" type="search" bind:value={query} placeholder="Поиск: название, адрес, подписка" />
      <select class="auto" bind:value={filter}>
        <option value="all">Все серверы</option>
        {#if ownServers(view).length > 0}<option value="own">Добавлены вручную</option>{/if}
        {#each view.subs as s (s.id)}<option value={'sub:' + s.id}>Подписка «{s.name}»</option>{/each}
      </select>
      <button disabled={pingRunning || shown.length === 0} onclick={() => ping(shown.map((s) => s.id))}>
        Проверить показанные ({shown.length})
      </button>
      <button class:primary={byPing} aria-pressed={byPing} onclick={() => (byPing = !byPing)}>По пингу</button>
      <button onclick={() => setCompact(!compact)}>{compact ? 'Крупно' : 'Компактно'}</button>
    </div>
    {#if pingRunning && pings}
      <div class="small progress">
        Проверяю серверы по одному: {pings.done} из {pings.total}.
        <button class="link" onclick={stopPing}>Остановить</button>
      </div>
    {/if}
    {#if shown.length === 0}
      <p class="muted">Ничего не найдено.</p>
    {:else}
      <ul class="list servers" class:compact>
        {#each shown as s (s.id)}
          {@const st = statusOf(s.id)}
          {@const pr = pings?.results[s.id]}
          <li>
            {#if renaming === s.id}
              <div class="row">
                <input class="grow" bind:value={newName} />
                <button class="primary" disabled={busy || !newName.trim()} onclick={() => rename(s.id)}>Сохранить</button>
                <button onclick={() => (renaming = '')}>Отмена</button>
              </div>
            {:else}
              <div class="row line">
                <span class="dot {st?.state ?? 'stopped'}"></span>
                <strong class="name" title={s.name}>{s.name}</strong>
                <span class="badge">{protocol(s.protocol)}</span>
                {#if view.settings.main === s.id}<span class="badge ok">основной</span>{/if}
                {#if s.missing}<span class="badge bad">нет в подписке</span>{/if}
                {#if s.source}<span class="muted small src">{subName(s.source)}</span>{/if}
                <span class="spacer"></span>
                <button
                  class="link ping"
                  class:fast={pr?.ms}
                  class:fail={pr && !pr.ms}
                  title={pr?.error ?? 'Проверить пинг этого сервера'}
                  disabled={pingRunning}
                  onclick={() => ping([s.id])}>{pingText(s.id)}</button
                >
                {#if view.settings.main !== s.id}
                  <button class="link" disabled={busy} onclick={() => run(() => api.setMain(s.id))}>Сделать основным</button>
                {/if}
                {#if !s.source}
                  <button class="link" disabled={busy} onclick={() => startRename(s.id, s.name)}>Переименовать</button>
                  <button class="link danger" disabled={busy} onclick={() => remove(s.id, s.name)}>Удалить</button>
                {/if}
              </div>
              {#if !compact}
                <div class="muted small detail">
                  {s.host}:{s.ports} ·
                  {st ? stateText[st.state] ?? st.state : 'не используется правилами'}
                  {#if st?.message && st.state !== 'connected'}— {st.message}{/if}
                  {#if pr?.error}· пинг: {pr.error}{/if}
                </div>
              {/if}
            {/if}
          </li>
        {/each}
      </ul>
      <p class="muted small">
        Пинг — время ответа на короткий запрос через сервер. Серверы запускаются по нескольку, а замеряются по одному,
        чтобы замеры не мешали друг другу.
      </p>
    {/if}
  {/if}
</div>

<Subs {view} {status} {onstate} />

<style>
  .grow {
    flex: 1;
    min-width: 160px;
    width: auto;
  }
  .detail {
    margin-top: 4px;
    padding-left: 15px;
    word-break: break-all;
  }
  .tools {
    margin-bottom: 8px;
  }
  .tools select {
    width: auto;
    max-width: 100%;
  }
  .search {
    flex: 1;
    min-width: 180px;
    width: auto;
  }
  .progress {
    margin-bottom: 6px;
  }
  .line {
    min-width: 0;
  }
  .name {
    min-width: 0;
    overflow-wrap: anywhere;
  }
  .servers.compact > li {
    padding: 6px 0;
  }
  .servers.compact .line {
    flex-wrap: nowrap;
  }
  .servers.compact .name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .servers.compact .src {
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    max-width: 30%;
  }
  .ping {
    font-variant-numeric: tabular-nums;
    white-space: nowrap;
  }
  .ping.fast {
    color: var(--ok);
  }
  .ping.fail {
    color: var(--bad);
  }
  ul {
    margin: 6px 0 0;
  }
</style>
