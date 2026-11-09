<script lang="ts">
  import { api, errorText } from '../lib/api';
  import type { StateView, Status } from '../lib/types';

  let { view, status, onstatus }: { view: StateView; status: Status; onstatus: (s: Status) => void } = $props();

  let busy = $state(false);
  let error = $state('');

  const stateText: Record<string, string> = {
    stopped: 'остановлен',
    connecting: 'подключается',
    connected: 'подключён',
    failed: 'ошибка',
  };

  async function toggle() {
    busy = true;
    error = '';
    try {
      onstatus((await api.routing(!status.running)).status);
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  function since(s: string): string {
    const d = new Date(s);
    return isNaN(d.getTime()) ? '' : d.toLocaleString('ru-RU');
  }

  function bytes(n: number): string {
    if (n < 1024) return `${n} Б`;
    if (n < 1 << 20) return `${(n / 1024).toFixed(1)} КБ`;
    if (n < 1 << 30) return `${(n / (1 << 20)).toFixed(1)} МБ`;
    return `${(n / (1 << 30)).toFixed(2)} ГБ`;
  }
</script>

<h1>Главная</h1>
<p class="lead">{view.edition}: маршрутизация устройств сети по правилам.</p>

<div class="notice">
  Бета-версия: проверена в CI, но не на настоящих роутерах. Держите доступ к роутеру по SSH, чтобы выключить HyRouter
  командой <code>/etc/init.d/hyrouter stop</code>, если сеть перестанет работать.
</div>

<div class="card hero">
  <div>
    <div class="state">
      <span class="dot" class:connected={status.running}></span>
      {status.running ? 'Маршрутизация работает' : 'Маршрутизация выключена'}
    </div>
    <div class="muted small">
      {#if status.running}
        с {since(status.since)} · соединений через relay: {status.relay}
      {:else}
        Сеть работает как без HyRouter.
      {/if}
    </div>
  </div>
  <div class="spacer"></div>
  <button class:primary={!status.running} disabled={busy} onclick={toggle}>
    {busy ? 'Подождите…' : status.running ? 'Выключить' : 'Включить'}
  </button>
</div>

{#if error}<div class="notice bad">{error}</div>{/if}
{#if status.error}<div class="notice bad">Последняя ошибка: {status.error}</div>{/if}
{#if status.guard}
  <div class="notice bad">
    Устройства сети не выходят в интернет: включена блокировка при загрузке, а HyRouter не запустился. Исправьте ошибку и
    включите HyRouter — или выключите его, и блокировка снимется.
  </div>
{/if}

{#if view.servers.length === 0}
  <div class="card">
    <h2>С чего начать</h2>
    <ol>
      <li>Добавьте сервер по ссылке <code>hysteria2://</code>{#if view.vless} или <code>vless://</code>{/if} в разделе <a href="#/servers">Серверы</a>.</li>
      <li>Дайте имена устройствам в разделе <a href="#/devices">Устройства</a>.</li>
      <li>Решите, что идёт через VPN, в разделе <a href="#/rules">Правила</a>.</li>
      <li>Нажмите «Включить».</li>
    </ol>
  </div>
{/if}

{#if status.issues.length > 0}
  <div class="card">
    <h2>Требует внимания</h2>
    <ul class="list">
      {#each status.issues as issue, i (i)}
        <li class="small">{issue}</li>
      {/each}
    </ul>
  </div>
{/if}

{#if status.servers.length > 0}
  <div class="card">
    <h2>Серверы в работе</h2>
    <ul class="list">
      {#each status.servers as s (s.id)}
        <li>
          <div class="row">
            <span class="dot {s.state}"></span>
            <strong>{s.name || s.id}</strong>
            <span class="muted small">{stateText[s.state] ?? s.state}{s.udp ? ', UDP' : ''}</span>
            <span class="spacer"></span>
            <span class="muted small">↑ {bytes(s.sent)} · ↓ {bytes(s.recv)}</span>
          </div>
          {#if s.message && s.state !== 'connected'}<div class="muted small msg">{s.message}</div>{/if}
        </li>
      {/each}
    </ul>
  </div>
{/if}

<style>
  .hero {
    display: flex;
    align-items: center;
    gap: 16px;
    flex-wrap: wrap;
  }
  .state {
    font-size: 1.15rem;
    font-weight: 600;
    margin-bottom: 2px;
  }
  .hero button {
    padding: 10px 22px;
  }
  ol {
    margin: 0;
    padding-left: 20px;
  }
  ol li {
    margin-bottom: 6px;
  }
  .msg {
    margin-top: 4px;
    padding-left: 15px;
  }
</style>
