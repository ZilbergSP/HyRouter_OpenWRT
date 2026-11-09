<script lang="ts">
  import { api, errorText } from '../lib/api';
  import type { StateView, Status } from '../lib/types';
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
  <h2>Ваши серверы</h2>
  {#if ownServers(view).length === 0}
    <p class="muted">Серверов, добавленных по ссылке, пока нет{view.subs.length ? ': серверы подписок — ниже' : ''}.</p>
  {:else}
    <ul class="list">
      {#each ownServers(view) as s (s.id)}
        {@const st = statusOf(s.id)}
        <li>
          {#if renaming === s.id}
            <div class="row">
              <input class="grow" bind:value={newName} />
              <button class="primary" disabled={busy || !newName.trim()} onclick={() => rename(s.id)}>Сохранить</button>
              <button onclick={() => (renaming = '')}>Отмена</button>
            </div>
          {:else}
            <div class="row">
              <span class="dot {st?.state ?? 'stopped'}"></span>
              <strong>{s.name}</strong>
              <span class="badge">{protocol(s.protocol)}</span>
              {#if view.settings.main === s.id}<span class="badge ok">основной</span>{/if}
              <span class="spacer"></span>
              {#if view.settings.main !== s.id}
                <button class="link" disabled={busy} onclick={() => run(() => api.setMain(s.id))}>Сделать основным</button>
              {/if}
              <button class="link" disabled={busy} onclick={() => startRename(s.id, s.name)}>Переименовать</button>
              <button class="link danger" disabled={busy} onclick={() => remove(s.id, s.name)}>Удалить</button>
            </div>
            <div class="muted small detail">
              {s.host}:{s.ports} ·
              {st ? stateText[st.state] ?? st.state : 'не используется правилами'}
              {#if st?.message && st.state !== 'connected'}— {st.message}{/if}
            </div>
          {/if}
        </li>
      {/each}
    </ul>
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
  ul {
    margin: 6px 0 0;
  }
</style>
