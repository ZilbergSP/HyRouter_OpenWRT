<script lang="ts">
  import { api, errorText } from '../lib/api';
  import type { RestorePlan, StateView } from '../lib/types';

  let { view, onstate }: { view: StateView; onstate: (v: StateView) => void } = $props();

  let plan = $state<RestorePlan | null>(null);
  let busy = $state(false);
  let error = $state('');
  let done = $state('');
  let input = $state<HTMLInputElement | null>(null);

  async function pick(e: Event) {
    const f = (e.currentTarget as HTMLInputElement).files?.[0];
    if (!f) return;
    error = '';
    done = '';
    plan = null;
    busy = true;
    try {
      plan = await api.restorePlan(JSON.parse(await f.text()));
    } catch (err) {
      error = err instanceof SyntaxError ? 'Это не файл резервной копии HyRouter.' : errorText(err);
    } finally {
      busy = false;
      if (input) input.value = '';
    }
  }

  async function restore() {
    if (!plan) return;
    busy = true;
    error = '';
    try {
      onstate((await api.restore(plan.token)).state);
      done = 'Настройки восстановлены.';
      plan = null;
    } catch (err) {
      error = errorText(err);
    } finally {
      busy = false;
    }
  }

  async function undo() {
    if (!confirm('Вернуть настройки, которые были до восстановления?')) return;
    busy = true;
    error = '';
    try {
      onstate((await api.undoRestore()).state);
      done = 'Прежние настройки возвращены.';
    } catch (err) {
      error = errorText(err);
    } finally {
      busy = false;
    }
  }

  function when(t: string): string {
    return new Date(t).toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'short' });
  }
</script>

<div class="card">
  <h2>Резервная копия</h2>
  <p class="muted small">
    Все настройки HyRouter в одном файле: серверы с паролями, подписки, правила, устройства, группы, обход DPI. Храните его
    как пароль.
  </p>
  <div class="row">
    <a class="button" href="/api/backup" download>Скачать копию</a>
    <label class="button">
      Восстановить из файла…
      <input bind:this={input} type="file" accept=".json,application/json" hidden onchange={pick} disabled={busy} />
    </label>
    {#if view.undo}
      <span class="spacer"></span>
      <button disabled={busy} onclick={undo}>Вернуть как было ({when(view.undo.at)})</button>
    {/if}
  </div>
  {#if view.undo?.partial}
    <div class="notice bad">
      Прошлое восстановление записалось не полностью. Нажмите «Вернуть как было», чтобы вернуть прежние настройки.
    </div>
  {/if}
  {#if plan}
    <div class="notice">
      <strong>Копия от {when(plan.created)} ({plan.edition})</strong>
      <div class="small">
        Серверов: {plan.servers}, подписок: {plan.subs}, групп: {plan.groups}, правил: {plan.rules}, устройств: {plan.devices}.
        Маршрутизация: {plan.routing ? 'включена' : 'выключена'}. Текущие настройки будут заменены; их можно будет вернуть.
      </div>
      {#if plan.warnings.length > 0}
        <ul class="small">
          {#each plan.warnings as w, i (i)}<li>{w}</li>{/each}
        </ul>
      {/if}
      <div class="row">
        <button class="primary" disabled={busy} onclick={restore}>Восстановить</button>
        <button disabled={busy} onclick={() => (plan = null)}>Отмена</button>
      </div>
    </div>
  {/if}
  {#if error}<div class="notice bad">{error}</div>{/if}
  {#if done}<div class="notice ok">{done}</div>{/if}
</div>

<style>
  .button {
    display: inline-flex;
    align-items: center;
    border: 1px solid var(--line);
    border-radius: 9px;
    padding: 8px 14px;
    background: var(--panel-2);
    color: var(--text);
    text-decoration: none;
    cursor: pointer;
    font: inherit;
  }
</style>
