<script lang="ts">
  import { onMount } from 'svelte';
  import { api, errorText, ApiError } from '../lib/api';
  import type { CoreView, UpdatesView } from '../lib/types';

  let u = $state<UpdatesView | null>(null);
  let error = $state('');
  let checking = $state(false);
  // HyRouter is being installed: the page waits for the new hyrouterd.
  let waiting = $state(false);

  async function load() {
    try {
      u = await api.updates();
      error = '';
      if (waiting && u.result?.done) waiting = false;
    } catch (e) {
      if (waiting) {
        // The new hyrouterd has no session yet: log in again.
        if (e instanceof ApiError && e.status === 401) location.reload();
        return; // restarting
      }
      error = errorText(e);
    }
  }

  onMount(() => {
    load();
    const t = setInterval(() => {
      if (waiting || u?.stage || u?.checking || u?.cores.some((c) => c.busy)) load();
    }, 2000);
    return () => clearInterval(t);
  });

  async function check() {
    checking = true;
    error = '';
    try {
      u = await api.checkUpdates();
    } catch (e) {
      error = errorText(e);
    } finally {
      checking = false;
    }
  }

  async function install() {
    if (!u?.update) return;
    const msg =
      `Установить HyRouter ${u.update.version}?\n\n` +
      'Служба перезапустится: примерно полминуты сеть будет без интернета. Страница переподключится сама.';
    if (!confirm(msg)) return;
    error = '';
    try {
      u = await api.installUpdate();
      waiting = true;
    } catch (e) {
      error = errorText(e);
    }
  }

  async function installCore(c: CoreView) {
    if (!c.update) return;
    const msg =
      `Установить ${c.title} ${v(c.update.version)}?\n\n` +
      'Серверы на этом ядре перезапустятся. Если те, что были подключены, не подключатся за минуту, вернётся прежнее ядро.';
    if (!confirm(msg)) return;
    error = '';
    try {
      u = await api.installCore(c.name);
    } catch (e) {
      error = errorText(e);
    }
  }

  async function rollback(c: CoreView) {
    if (!confirm(`Вернуть ${c.title} ${v(c.previous ?? '')}? Серверы на этом ядре перезапустятся.`)) return;
    error = '';
    try {
      u = await api.rollbackCore(c.name);
    } catch (e) {
      error = errorText(e);
    }
  }

  // v shows a core's version without Hysteria's "app/".
  function v(s: string): string {
    return s.replace(/app\//g, '');
  }

  function when(t?: string): string {
    if (!t) return '';
    const d = new Date(t);
    return isNaN(d.getTime()) ? '' : d.toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'short' });
  }

  function pct(p: number): number {
    return Math.round(p * 100);
  }
</script>

<div class="card">
  <div class="row head">
    <h2>Обновления</h2>
    <span class="spacer"></span>
    {#if u}
      <button disabled={checking || u.checking} onclick={check}>{checking || u.checking ? 'Проверяю…' : 'Проверить'}</button>
    {/if}
  </div>
  {#if u}
    <p class="muted small">
      HyRouter {u.version}{u.package ? ` (пакет ${u.package})` : ''}.
      {u.dev
        ? 'Это сборка не из выпуска: обновления проверяются только кнопкой.'
        : 'Роутер сам проверяет обновления раз в сутки, а ставит их только по кнопке.'}
      {#if u.checked}Проверено {when(u.checked)}.{/if}
    </p>

    {#if u.result}
      {#if u.result.ok}
        <div class="notice ok">HyRouter обновлён с {u.result.from} до {u.result.to}.</div>
      {:else if u.result.done}
        <div class="notice bad">
          HyRouter {u.result.to} не установился, работает {u.version}.
          {#if u.result.lines?.length}<pre>{u.result.lines.join('\n')}</pre>{/if}
        </div>
      {:else}
        <div class="notice">Устанавливается HyRouter {u.result.to}…</div>
      {/if}
    {/if}
    {#if u.error}<div class="notice bad">Не удалось проверить: {u.error}</div>{/if}
    {#if u.installError}<div class="notice bad">{u.installError}</div>{/if}

    {#if u.update}
      <div class="avail">
        <div class="row">
          <strong>Доступна версия {u.update.version}</strong>
          {#if u.update.published}<span class="muted small">от {when(u.update.published)}</span>{/if}
          <span class="spacer"></span>
          {#if u.stage === 'downloading'}
            <span class="small">Скачиваю… {pct(u.progress)}%</span>
          {:else if u.stage === 'installing' || waiting}
            <span class="small">Устанавливаю: HyRouter перезапустится…</span>
          {:else}
            <button class="primary" onclick={install}>Обновить</button>
          {/if}
        </div>
        {#if u.update.notes}
          <details>
            <summary>Что нового</summary>
            <pre class="notes">{u.update.notes}</pre>
          </details>
        {/if}
        {#if u.update.page}<a class="small" href={u.update.page} target="_blank" rel="noreferrer">Страница выпуска</a>{/if}
      </div>
    {:else if u.checked && !u.error && !u.dev}
      <p class="small">Установлена последняя версия.</p>
    {/if}

    <h3>Ядра</h3>
    {#if u.embedded}
      <p class="muted small">В HyRouter Lite Hysteria встроена в hyrouterd и обновляется вместе с HyRouter.</p>
    {:else}
      <p class="muted small">
        Новые выпуски Hysteria и Xray проверяются по контрольным суммам и пробным запуском. После установки серверы на ядре
        перезапускаются; если те, что были подключены, не подключатся за минуту, вернётся прежнее ядро.
      </p>
      {#each u.cores as c (c.name)}
        <div class="core">
          <div class="row">
            <strong>{c.title} {v(c.version)}</strong>
            <span class="muted small">{c.updated ? `обновлено, в выпуске HyRouter — ${v(c.pinned)}` : 'из выпуска HyRouter'}</span>
            <span class="spacer"></span>
            {#if c.busy}
              <span class="small">{c.progress > 0 && c.progress < 1 ? `Скачиваю… ${pct(c.progress)}%` : 'Ставлю и проверяю…'}</span>
            {:else}
              {#if c.update}<button class="primary" onclick={() => installCore(c)}>Обновить до {v(c.update.version)}</button>{/if}
              {#if c.updated && c.previous}<button onclick={() => rollback(c)}>Вернуть {v(c.previous)}</button>{/if}
            {/if}
          </div>
          {#if c.error}<div class="notice bad">{c.error}</div>{/if}
          {#if c.checkError}<div class="muted small">Не удалось проверить: {c.checkError}</div>{/if}
          {#if c.note}<div class="notice {c.failed ? 'bad' : 'ok'}">{c.note}</div>{/if}
          {#if c.update?.notes && !c.busy}
            <details>
              <summary>Что нового в {v(c.update.version)}</summary>
              <pre class="notes">{c.update.notes}</pre>
            </details>
          {/if}
        </div>
      {/each}
    {/if}
  {/if}
  {#if error}<div class="notice bad">{error}</div>{/if}
</div>

<style>
  .head h2 {
    margin: 0;
  }
  h3 {
    margin: 18px 0 4px;
    font-size: 1rem;
  }
  .avail,
  .core {
    border: 1px solid var(--line);
    border-radius: 10px;
    padding: 10px 12px;
    background: var(--panel-2);
    margin: 8px 0;
  }
  details {
    margin-top: 6px;
  }
  pre {
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    font-size: 0.82rem;
    max-height: 320px;
    overflow: auto;
    margin: 6px 0 0;
  }
  .notice {
    margin: 8px 0;
  }
</style>
