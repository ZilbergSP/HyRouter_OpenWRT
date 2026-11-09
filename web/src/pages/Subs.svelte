<script lang="ts">
  import { api, errorText } from '../lib/api';
  import { plural } from '../lib/targets';
  import type { StateView, Status, Sub } from '../lib/types';

  let { view, status, onstate }: { view: StateView; status: Status; onstate: (v: StateView) => void } = $props();

  const intervals = [
    { h: 0, name: 'вручную' },
    { h: 1, name: 'каждый час' },
    { h: 6, name: 'раз в 6 часов' },
    { h: 12, name: 'раз в 12 часов' },
    { h: 24, name: 'раз в сутки' },
  ];

  let link = $state('');
  let name = $state('');
  let every = $state(12);
  let busy = $state('');
  let error = $state('');
  let note = $state('');
  let open = $state<Record<string, boolean>>({});
  let editing = $state('');
  let form = $state({ name: '', url: '', intervalH: 12, enabled: true });

  function serverState(id: string): string {
    return status.servers.find((s) => s.id === id)?.state ?? 'stopped';
  }

  function servers(s: Sub) {
    return view.servers.filter((p) => p.source === 'sub:' + s.id);
  }

  function statsText(st: { added: number; updated: number; removed: number; missingKept: number }): string {
    const parts = [];
    if (st.added) parts.push(`новых: ${st.added}`);
    if (st.updated) parts.push(`обновлено: ${st.updated}`);
    if (st.removed) parts.push(`убрано: ${st.removed}`);
    if (st.missingKept) parts.push(`оставлено, хотя их нет в подписке: ${st.missingKept}`);
    return parts.join(', ') || 'без изменений';
  }

  function when(t?: string): string {
    if (!t || t.startsWith('0001')) return 'ещё не обновлялась';
    return new Date(t).toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'short' });
  }

  async function act(key: string, f: () => Promise<{ state: StateView }>): Promise<boolean> {
    busy = key;
    error = '';
    note = '';
    try {
      onstate((await f()).state);
      return true;
    } catch (e) {
      error = errorText(e);
      return false;
    } finally {
      busy = '';
    }
  }

  async function add(e: SubmitEvent) {
    e.preventDefault();
    busy = 'add';
    error = '';
    note = '';
    try {
      const r = await api.addSub({ url: link.trim(), name: name.trim(), intervalH: every, enabled: every > 0 });
      onstate(r.state);
      note = `Подписка добавлена: ${statsText(r.stats)}.`;
      link = '';
      name = '';
    } catch (err) {
      error = errorText(err);
    } finally {
      busy = '';
    }
  }

  async function update(s: Sub) {
    busy = s.id;
    error = '';
    note = '';
    try {
      const r = await api.updateSub(s.id);
      onstate(r.state);
      note = `«${s.name}» обновлена: ${statsText(r.stats)}.`;
    } catch (err) {
      error = `«${s.name}»: ${errorText(err)}`;
    } finally {
      busy = '';
    }
  }

  function startEdit(s: Sub) {
    editing = s.id;
    form = { name: s.name, url: '', intervalH: s.intervalH, enabled: s.enabled };
  }

  async function saveEdit(s: Sub) {
    const ok = await act(s.id, () =>
      api.editSub(s.id, { name: form.name.trim(), url: form.url.trim(), intervalH: form.intervalH, enabled: form.intervalH > 0 }),
    );
    if (ok) editing = '';
  }

  async function remove(s: Sub) {
    if (!confirm(`Удалить подписку «${s.name}» и её серверы? Серверы, которые выбраны в правилах или группах, останутся.`)) return;
    await act(s.id, () => api.deleteSub(s.id));
  }
</script>

<form class="card" onsubmit={add}>
  <h2>Добавить подписку</h2>
  <p class="muted small">
    Ссылка подписки от панели (Remnawave, Marzban и других): HyRouter загрузит из неё серверы Hysteria 2{view.vless
      ? ' и VLESS'
      : ''} и будет обновлять их сам. Ссылка хранится только на роутере.
  </p>
  <label class="field">
    <span>Ссылка подписки</span>
    <input bind:value={link} placeholder="https://…" required />
  </label>
  <div class="two">
    <label class="field">
      <span>Название (необязательно)</span>
      <input bind:value={name} placeholder="Как называет панель" />
    </label>
    <label class="field">
      <span>Обновлять</span>
      <select bind:value={every}>
        {#each intervals as i (i.h)}<option value={i.h}>{i.name}</option>{/each}
      </select>
    </label>
  </div>
  <button class="primary" type="submit" disabled={busy !== '' || !link.trim()}>{busy === 'add' ? 'Загружаю…' : 'Добавить'}</button>
</form>

{#if error}<div class="notice bad">{error}</div>{/if}
{#if note}<div class="notice ok">{note}</div>{/if}

{#if view.subs.length > 0}
  <div class="card">
    <h2>Подписки</h2>
    <ul class="list">
      {#each view.subs as s (s.id)}
        {@const list = servers(s)}
        <li>
          {#if editing === s.id}
            <div class="edit">
              <label class="field">
                <span>Название</span>
                <input bind:value={form.name} />
              </label>
              <label class="field">
                <span>Новая ссылка (пусто — оставить прежнюю)</span>
                <input bind:value={form.url} placeholder="https://…" />
              </label>
              <label class="field">
                <span>Обновлять</span>
                <select bind:value={form.intervalH}>
                  {#each intervals as i (i.h)}<option value={i.h}>{i.name}</option>{/each}
                </select>
              </label>
              <div class="row">
                <button class="primary" disabled={busy !== ''} onclick={() => saveEdit(s)}>Сохранить</button>
                <button onclick={() => (editing = '')}>Отмена</button>
              </div>
            </div>
          {:else}
            <div class="row">
              <strong>{s.name}</strong>
              <span class="badge">{s.servers} {plural(s.servers, 'сервер', 'сервера', 'серверов')}</span>
              {#if s.info?.level === 'out'}<span class="badge bad">закончилась</span>{:else if s.info?.level === 'low'}<span
                  class="badge warn">заканчивается</span
                >{/if}
              {#if s.lastError}<span class="badge bad">ошибка обновления</span>{/if}
              <span class="spacer"></span>
              <button class="link" disabled={busy !== ''} onclick={() => update(s)}>{busy === s.id ? 'Обновляю…' : 'Обновить'}</button>
              <button class="link" disabled={busy !== ''} onclick={() => startEdit(s)}>Изменить</button>
              <button class="link danger" disabled={busy !== ''} onclick={() => remove(s)}>Удалить</button>
            </div>
            <div class="muted small detail">
              {s.url} · {intervals.find((i) => i.h === s.intervalH)?.name ?? `раз в ${s.intervalH} ч`} · обновлена {when(s.lastUpdate)}{s.viaVPN
                ? ' (через VPN: напрямую панель не ответила)'
                : ''}
            </div>
            {#if s.info}
              <div class="small detail">
                {s.info.summary}{s.info.details ? ` (${s.info.details})` : ''}
                {#if s.info.percent >= 0}
                  <div class="bar"><span style="width: {s.info.usedPct}%"></span></div>
                {/if}
              </div>
            {/if}
            {#if s.lastError}<div class="small detail err">Последнее обновление не удалось: {s.lastError}</div>{/if}
            {#if s.warnings?.length}
              <details class="small detail">
                <summary>Не всё перенесено ({s.warnings.length})</summary>
                <ul>
                  {#each s.warnings as w, i (i)}<li>{w}</li>{/each}
                </ul>
              </details>
            {/if}
            {#if list.length > 0}
              <details class="small detail" bind:open={open[s.id]}>
                <summary>Серверы{s.missing ? ` (нет в подписке, но выбраны в правилах: ${s.missing})` : ''}</summary>
                {#if open[s.id]}
                  <ul class="servers">
                    {#each list as p (p.id)}
                      <li>
                        <span class="dot {serverState(p.id)}"></span>
                        {p.name}
                        {#if p.missing}<span class="badge warn">нет в подписке</span>{/if}
                        {#if view.settings.main === p.id}<span class="badge ok">основной</span>{:else}
                          <button class="link" disabled={busy !== ''} onclick={() => act(p.id, () => api.setMain(p.id))}
                            >Сделать основным</button
                          >
                        {/if}
                        {#if p.missing}
                          <button class="link danger" disabled={busy !== ''} onclick={() => act(p.id, () => api.deleteServer(p.id))}
                            >Удалить</button
                          >
                        {/if}
                      </li>
                    {/each}
                  </ul>
                {/if}
              </details>
            {/if}
          {/if}
        </li>
      {/each}
    </ul>
  </div>
{/if}

<style>
  .two {
    display: grid;
    grid-template-columns: 2fr 1fr;
    gap: 12px;
  }
  .detail {
    margin-top: 4px;
    word-break: break-word;
  }
  .err {
    color: var(--bad);
  }
  .bar {
    height: 6px;
    border-radius: 3px;
    background: var(--panel-2);
    border: 1px solid var(--line);
    margin-top: 4px;
    max-width: 320px;
    overflow: hidden;
  }
  .bar span {
    display: block;
    height: 100%;
    background: var(--accent);
  }
  .servers {
    list-style: none;
    padding-left: 4px;
    margin: 6px 0 0;
    max-height: 360px;
    overflow: auto;
  }
  .servers li {
    padding: 2px 0;
  }
  .edit {
    display: grid;
    gap: 4px;
  }
  @media (max-width: 640px) {
    .two {
      grid-template-columns: 1fr;
    }
  }
</style>
