<script lang="ts">
  import { api, errorText } from '../lib/api';
  import type { Action, Rule, RulesConfig, StateView } from '../lib/types';
  import RuleEditor from './RuleEditor.svelte';

  let { view, onstate }: { view: StateView; onstate: (v: StateView) => void } = $props();

  function fresh(): RulesConfig {
    const c = $state.snapshot(view.rules) as RulesConfig;
    c.rules = c.rules ?? [];
    return c;
  }

  let cfg = $state(fresh());
  let dirty = $state(false);
  let editing = $state<number | null>(null);
  let busy = $state(false);
  let error = $state('');
  let saved = $state(false);

  const actionText: Record<Action, string> = { tunnel: 'Через VPN', direct: 'Напрямую', block: 'Блок' };

  function serverName(id?: string): string {
    if (!id) {
      const m = view.servers.find((s) => s.id === view.settings.main);
      return m ? m.name : 'основной сервер не выбран';
    }
    return view.servers.find((s) => s.id === id)?.name ?? 'удалённый сервер';
  }

  function deviceText(items?: string[]): string {
    if (!items?.length) return 'все устройства';
    return items
      .map((d) => (d.startsWith('dev:') ? (view.devices.find((x) => x.id === d.slice(4))?.name ?? d.slice(4)) : d))
      .join(', ');
  }

  function sitesText(items?: string[]): string {
    if (!items?.length) return 'любые сайты';
    const shown = items.slice(0, 3).join(', ');
    return items.length > 3 ? `${shown} и ещё ${items.length - 3}` : shown;
  }

  function portsText(r: Rule): string {
    const proto = r.protocol ? r.protocol.toUpperCase() : '';
    if (!r.ports) return proto;
    return `${proto ? proto + ' ' : ''}порты ${r.ports}`;
  }

  function change(f: () => void) {
    f();
    dirty = true;
    saved = false;
  }

  function move(i: number, d: number) {
    const j = i + d;
    if (j < 0 || j >= cfg.rules.length) return;
    change(() => {
      const r = cfg.rules;
      [r[i], r[j]] = [r[j], r[i]];
    });
  }

  function remove(i: number) {
    if (!confirm(`Удалить правило «${cfg.rules[i].name || 'без названия'}»?`)) return;
    change(() => cfg.rules.splice(i, 1));
  }

  function toggle(i: number, on: boolean) {
    change(() => {
      if (on) delete cfg.rules[i].enabled;
      else cfg.rules[i].enabled = false;
    });
  }

  function edited(r: Rule) {
    change(() => {
      if (editing === -1) cfg.rules.push(r);
      else if (editing !== null) cfg.rules[editing] = r;
    });
    editing = null;
  }

  async function save() {
    busy = true;
    error = '';
    try {
      const r = await api.saveRules($state.snapshot(cfg) as RulesConfig);
      onstate(r.state);
      cfg = $state.snapshot(r.state.rules) as RulesConfig;
      dirty = false;
      saved = true;
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  function revert() {
    cfg = fresh();
    dirty = false;
    editing = null;
    error = '';
  }

  const blank: Rule = { name: '', action: 'tunnel' };
</script>

<h1>Правила</h1>
<p class="lead">
  Каждое новое соединение проверяется по правилам сверху вниз; срабатывает первое подходящее. Если не подошло ни одно —
  действует «Всё остальное».
</p>

{#if dirty}
  <div class="savebar card">
    <span>Есть несохранённые изменения.</span>
    <span class="spacer"></span>
    <button onclick={revert} disabled={busy}>Отменить</button>
    <button class="primary" onclick={save} disabled={busy}>{busy ? 'Применяю…' : 'Сохранить и применить'}</button>
  </div>
{/if}
{#if error}<div class="notice bad">{error}</div>{/if}
{#if saved}<div class="notice ok">Правила применены. Уже открытые соединения сохраняют прежний маршрут.</div>{/if}

{#if editing === -1}
  <RuleEditor rule={blank} devices={view.devices} servers={view.servers} onsave={edited} oncancel={() => (editing = null)} />
{/if}

<div class="card">
  <div class="row head">
    <h2>Правила</h2>
    <span class="spacer"></span>
    <button class="primary" disabled={editing !== null} onclick={() => (editing = -1)}>Добавить правило</button>
  </div>
  {#if cfg.rules.length === 0}
    <p class="muted">Правил пока нет: всё идёт по «Всё остальное».</p>
  {:else}
    <ol class="list rules">
      {#each cfg.rules as r, i (i)}
        <li class:off={r.enabled === false}>
          {#if editing === i}
            <RuleEditor rule={r} devices={view.devices} servers={view.servers} onsave={edited} oncancel={() => (editing = null)} />
          {:else}
            <div class="row">
              <span class="num">{i + 1}</span>
              <strong>{r.name || 'Без названия'}</strong>
              <span class="badge {r.action === 'direct' ? 'ok' : r.action === 'block' ? 'bad' : ''}">
                {actionText[r.action]}{r.action === 'tunnel' ? ': ' + serverName(r.profile) : ''}
              </span>
              <span class="spacer"></span>
              <label class="check small"><input type="checkbox" checked={r.enabled !== false} onchange={(e) => toggle(i, e.currentTarget.checked)} /> вкл.</label>
              <button class="link" aria-label="Выше" disabled={i === 0} onclick={() => move(i, -1)}>↑</button>
              <button class="link" aria-label="Ниже" disabled={i === cfg.rules.length - 1} onclick={() => move(i, 1)}>↓</button>
              <button class="link" disabled={editing !== null} onclick={() => (editing = i)}>Изменить</button>
              <button class="link danger" onclick={() => remove(i)}>Удалить</button>
            </div>
            <div class="muted small summary">
              {deviceText(r.devices)} · {sitesText(r.domains)}{portsText(r) ? ' · ' + portsText(r) : ''}
            </div>
          {/if}
        </li>
      {/each}
    </ol>
  {/if}
</div>

<div class="card">
  <h2>Всё остальное</h2>
  <div class="row">
    <select class="auto" value={cfg.defaultAction} onchange={(e) => change(() => (cfg.defaultAction = e.currentTarget.value as Action))}>
      <option value="direct">Напрямую</option>
      <option value="tunnel">Через VPN</option>
      <option value="block">Блокировать</option>
    </select>
    {#if cfg.defaultAction === 'tunnel'}
      <select class="auto" value={cfg.defaultProfile ?? ''} onchange={(e) => change(() => (cfg.defaultProfile = e.currentTarget.value || undefined))}>
        <option value="">Основной сервер</option>
        {#each view.servers as s (s.id)}
          <option value={s.id}>{s.name}</option>
        {/each}
      </select>
    {/if}
  </div>
  <p class="muted small hint">
    «Через VPN» без доступного сервера соединение отклоняется: такой трафик никогда не идёт напрямую.
  </p>
</div>

<style>
  .savebar {
    display: flex;
    gap: 10px;
    align-items: center;
    position: sticky;
    top: 8px;
    z-index: 2;
    border-color: var(--accent);
  }
  .head h2 {
    margin: 0;
  }
  .rules {
    margin-top: 10px;
  }
  .rules li.off {
    opacity: 0.55;
  }
  .num {
    display: inline-grid;
    place-items: center;
    width: 24px;
    height: 24px;
    border-radius: 50%;
    background: var(--panel-2);
    border: 1px solid var(--line);
    font-size: 0.8rem;
    color: var(--muted);
  }
  .summary {
    margin-top: 4px;
    padding-left: 34px;
  }
  .auto {
    width: auto;
  }
  .hint {
    margin-top: 10px;
  }
</style>
