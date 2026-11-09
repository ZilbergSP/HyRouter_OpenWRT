<script lang="ts">
  import { api, errorText } from '../lib/api';
  import { ownServers, plural } from '../lib/targets';
  import type { Group, GroupStatus, StateView, Status, Strategy } from '../lib/types';

  let { view, status, onstate }: { view: StateView; status: Status; onstate: (v: StateView) => void } = $props();

  let busy = $state(false);
  let error = $state('');
  let editing = $state<string | null>(null); // a group ID, or "new"
  let form = $state(blank());
  let probe = $state(probeInit());

  function probeInit() {
    return { url: view.groups.probe?.url ?? '', every: view.groups.probe?.intervalSec ?? 0 };
  }

  const hints: Record<Strategy, string> = {
    failover: 'Всё идёт через первый доступный сервер списка; если он не работает — через следующий.',
    latency: 'Новые соединения идут через сервер с самой низкой задержкой.',
    roundrobin: 'Новые соединения по очереди идут через разные серверы.',
    random: 'Каждое новое соединение — через случайный доступный сервер.',
    sticky: 'Один сайт с одного устройства всегда идёт через один сервер, пока тот работает.',
  };

  function blank(): Group {
    return { id: '', name: '', strategy: 'failover', members: [], subs: [], revert: true, toleranceMs: 0, switchAfterErrors: 0 };
  }

  function edit(g: Group | null) {
    form = g ? ($state.snapshot(g) as Group) : blank();
    form.subs = form.subs ?? [];
    editing = g ? g.id : 'new';
    error = '';
  }

  function serverName(id: string): string {
    return view.servers.find((s) => s.id === id)?.name ?? id;
  }

  function statusOf(id: string): GroupStatus | undefined {
    return status.groups.find((g) => g.id === id);
  }

  function serverState(id: string): string {
    return status.servers.find((s) => s.id === id)?.state ?? 'stopped';
  }

  function toggle(id: string, on: boolean) {
    form.members = on ? [...form.members, id] : form.members.filter((m) => m !== id);
  }

  function move(i: number, d: number) {
    const m = [...form.members];
    [m[i], m[i + d]] = [m[i + d], m[i]];
    form.members = m;
  }

  async function run(f: () => Promise<{ state: StateView }>): Promise<boolean> {
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

  async function save(e: SubmitEvent) {
    e.preventDefault();
    const g = $state.snapshot(form) as Group;
    g.name = g.name.trim();
    const ok = editing === 'new' ? await run(() => api.addGroup(g)) : await run(() => api.editGroup(g));
    if (ok) editing = null;
  }

  async function remove(g: Group) {
    if (!confirm(`Удалить группу «${g.name}»? Правила, которые на неё ссылаются, будут отклонять трафик, пока вы не выберете другой сервер.`)) return;
    await run(() => api.deleteGroup(g.id));
  }

  async function saveProbe(e: SubmitEvent) {
    e.preventDefault();
    await run(() => api.setGroupProbe({ url: probe.url.trim() || undefined, intervalSec: probe.every || undefined }));
  }

  function latency(ms: number): string {
    return ms > 0 ? `${ms} мс` : '—';
  }

  const reasons: Record<string, string> = {
    errors: 'пропускается: соединения через него не открывались',
    trial: 'проверяется одним соединением',
    probe: 'пропускается: проверка задержки не прошла',
  };
</script>

<h1>Группы серверов</h1>
<p class="lead">
  Группа — это несколько серверов, из которых HyRouter сам выбирает рабочий. В правилах группу можно выбрать вместо сервера.
  Если ни один сервер группы не работает, соединение отклоняется, а не идёт напрямую.
</p>

{#if error}<div class="notice bad">{error}</div>{/if}

{#if editing !== null}
  <form class="card editor" onsubmit={save}>
    <h2>{editing === 'new' ? 'Новая группа' : `Группа «${form.name}»`}</h2>
    <label class="field">
      <span>Название</span>
      <input bind:value={form.name} placeholder="Например, Европа" required />
    </label>
    <label class="field">
      <span>Как выбирать сервер</span>
      <select bind:value={form.strategy}>
        {#each view.strategies as s (s.id)}
          <option value={s.id}>{s.name}</option>
        {/each}
      </select>
    </label>
    <p class="muted small">{hints[form.strategy]}</p>

    <div class="field">
      <span class="label">Серверы группы{form.strategy === 'failover' ? ' (по порядку)' : ''}</span>
      {#if form.members.length > 0}
        <ol class="members">
          {#each form.members as id, i (id)}
            <li>
              <span>{serverName(id)}</span>
              <span class="spacer"></span>
              <button type="button" class="link" aria-label="Выше" disabled={i === 0} onclick={() => move(i, -1)}>↑</button>
              <button type="button" class="link" aria-label="Ниже" disabled={i === form.members.length - 1} onclick={() => move(i, 1)}>↓</button>
              <button type="button" class="link danger" onclick={() => toggle(id, false)}>Убрать</button>
            </li>
          {/each}
        </ol>
      {/if}
      <div class="chips">
        {#each ownServers(view).filter((s) => !form.members.includes(s.id)) as s (s.id)}
          <button type="button" class="chip" onclick={() => toggle(s.id, true)}>+ {s.name}</button>
        {/each}
      </div>
    </div>

    {#if form.strategy === 'failover'}
      <label class="check field">
        <input type="checkbox" bind:checked={form.revert} /> Возвращаться к серверу выше по списку, когда он снова заработает
      </label>
    {/if}
    {#if form.strategy === 'latency'}
      <label class="field">
        <span>Переходить на более быстрый сервер, если он быстрее на, мс (пусто — 50)</span>
        <input type="number" min="10" max="1000" bind:value={form.toleranceMs} />
      </label>
    {/if}
    <label class="field">
      <span>Пропускать сервер после стольких неудачных соединений подряд (0 — не пропускать)</span>
      <input type="number" min="0" max="20" bind:value={form.switchAfterErrors} />
    </label>
    {#if form.members.length > view.groupRun}
      <p class="muted small">
        Одновременно работают {view.groupRun} {plural(view.groupRun, 'лучший сервер', 'лучших сервера', 'лучших серверов')} группы;
        остальные HyRouter проверяет по нескольку и подменяет ими медленные.
      </p>
    {/if}

    <div class="row">
      <button class="primary" type="submit" disabled={busy}>Сохранить</button>
      <button type="button" onclick={() => (editing = null)}>Отмена</button>
    </div>
  </form>
{/if}

<div class="card">
  <div class="row head">
    <h2>Ваши группы</h2>
    <span class="spacer"></span>
    <button class="primary" disabled={editing !== null || view.servers.length === 0} onclick={() => edit(null)}>Создать группу</button>
  </div>
  {#if view.groups.groups.length === 0}
    <p class="muted">Групп пока нет.{view.servers.length === 0 ? ' Сначала добавьте серверы.' : ''}</p>
  {:else}
    <ul class="list">
      {#each view.groups.groups as g (g.id)}
        {@const st = statusOf(g.id)}
        <li>
          <div class="row">
            <strong>{g.name}</strong>
            <span class="badge">{view.strategies.find((s) => s.id === g.strategy)?.name ?? g.strategy}</span>
            {#if view.settings.main === g.id}<span class="badge ok">основная</span>{/if}
            {#if st?.used}
              <span class="badge {st.up > 0 ? 'ok' : 'bad'}">работает {st.up} из {st.members.length}</span>
            {/if}
            <span class="spacer"></span>
            {#if view.settings.main !== g.id}
              <button class="link" disabled={busy} onclick={() => run(() => api.setMain(g.id))}>Сделать основной</button>
            {/if}
            <button class="link" disabled={busy || editing !== null} onclick={() => edit(g)}>Изменить</button>
            <button class="link danger" disabled={busy} onclick={() => remove(g)}>Удалить</button>
          </div>
          {#if st?.used}
            <ul class="mlist small">
              {#each st.members as m (m.id)}
                <li class:off={!st.running.includes(m.id)}>
                  <span class="dot {serverState(m.id)}"></span>
                  {serverName(m.id)}
                  {#if st.active === m.id}<span class="badge ok">сейчас</span>{/if}
                  <span class="muted">· {latency(m.latencyMs)}</span>
                  {#if !st.running.includes(m.id)}<span class="muted">· ждёт очереди</span>{/if}
                  {#if m.skipped}<span class="muted">· {reasons[m.reason ?? ''] ?? 'пропускается'}</span>{/if}
                  {#if m.error}<span class="muted">· {m.error}</span>{/if}
                </li>
              {/each}
            </ul>
            {#if st.probeBroken}
              <p class="muted small">Адрес проверки задержки не открылся ни через один сервер: проверьте его ниже.</p>
            {/if}
            {#if st.rejected > 0}
              <p class="muted small">Отклонено соединений, когда не работал ни один сервер: {st.rejected}</p>
            {/if}
          {:else}
            <div class="muted small">
              {g.members.length > 0 ? g.members.map(serverName).join(', ') : 'серверов нет'}
              · не используется правилами или HyRouter выключен
            </div>
          {/if}
        </li>
      {/each}
    </ul>
  {/if}
</div>

<form class="card" onsubmit={saveProbe}>
  <h2>Проверка задержки</h2>
  <p class="muted small">
    HyRouter открывает этот адрес через каждый сервер используемых групп и так узнаёт, какой сервер быстрее и какой не работает.
  </p>
  <div class="two">
    <label class="field">
      <span>Адрес (пусто — http://cp.cloudflare.com/generate_204)</span>
      <input bind:value={probe.url} placeholder="http://cp.cloudflare.com/generate_204" />
    </label>
    <label class="field">
      <span>Раз в, секунд (30–600, пусто — 60)</span>
      <input type="number" min="0" max="600" bind:value={probe.every} />
    </label>
  </div>
  <button type="submit" disabled={busy}>Сохранить</button>
</form>

<style>
  .editor {
    border-color: var(--accent);
  }
  .head h2 {
    margin: 0;
  }
  .label {
    display: block;
    font-size: 0.86rem;
    color: var(--muted);
    margin-bottom: 6px;
  }
  .members {
    margin: 0 0 8px;
    padding-left: 22px;
  }
  .members li {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 3px 0;
  }
  .chips {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }
  .chip {
    border-radius: 999px;
    padding: 4px 12px;
  }
  .mlist {
    list-style: none;
    margin: 8px 0 0;
    padding-left: 4px;
  }
  .mlist li {
    padding: 2px 0;
  }
  .mlist li.off {
    opacity: 0.6;
  }
  .two {
    display: grid;
    grid-template-columns: 2fr 1fr;
    gap: 12px;
  }
  @media (max-width: 640px) {
    .two {
      grid-template-columns: 1fr;
    }
  }
</style>
