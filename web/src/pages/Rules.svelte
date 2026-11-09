<script lang="ts">
  import { api, errorText } from '../lib/api';
  import type { Action, GeoStatus, Rule, RulesConfig, StateView } from '../lib/types';
  import RuleEditor from './RuleEditor.svelte';
  import TargetSelect from '../lib/TargetSelect.svelte';
  import FallbackList from '../lib/FallbackList.svelte';
  import { mainName, targetName } from '../lib/targets';
  import {
    applyScheme,
    missingLists,
    ruleFromTemplate,
    schemes,
    schemeTemplates,
    sourceName,
    templates,
    tplGroups,
    type Scheme,
    type Template,
  } from '../lib/templates';

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

  function serverName(r: Rule): string {
    const main = r.profile ? targetName(view, r.profile) : view.settings.main ? mainName(view) : 'основной сервер не выбран';
    return r.fallback?.length ? `${main} + запасных: ${r.fallback.length}` : main;
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
  // The rule the editor of a new rule starts from: blank or a template's.
  let draft = $state<{ rule: Rule; title?: string }>({ rule: blank });

  function add() {
    draft = { rule: blank };
    picking = false;
    editing = -1;
  }

  // «Шаблоны»: the rule database in use, read when the list opens, tells
  // which lists of the templates it lacks (null: not known, no warnings).
  let picking = $state(false);
  let geo = $state<GeoStatus | null>(null);

  async function openTemplates() {
    picking = true;
    try {
      geo = await api.geo();
    } catch {
      geo = null;
    }
  }

  function fromTemplate(t: Template) {
    draft = { rule: ruleFromTemplate(t), title: `Новое правило: ${t.name}` };
    picking = false;
    editing = -1;
  }

  function schemeWarning(sc: Scheme): string {
    if (!geo) return '';
    if (sc.source && sc.source !== geo.source) {
      return `Рассчитана на базу ${sourceName(geo, sc.source)}: выберите её в «Настройки → Базы geosite и geoip».`;
    }
    const miss = missingLists(
      schemeTemplates(sc).flatMap((t) => t.domains),
      geo,
    );
    return miss ? `Часть списков не сработает: ${miss}.` : '';
  }

  function useScheme(sc: Scheme) {
    const rest = sc.rest === 'direct' ? 'напрямую' : 'через VPN';
    const msg =
      `«${sc.name}»\n\nПравила схемы встанут в начало списка и будут действовать для всех устройств, ` +
      `«Всё остальное» станет «${rest}». Ваши правила останутся ниже. Изменения применятся кнопкой «Сохранить и применить».`;
    if (!confirm(msg)) return;
    picking = false;
    change(() => (cfg = applyScheme($state.snapshot(cfg) as RulesConfig, sc)));
  }
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
  <RuleEditor rule={draft.rule} title={draft.title} {view} onsave={edited} oncancel={() => (editing = null)} />
{/if}

{#if picking}
  <div class="card picker">
    <div class="row head">
      <h2>Шаблоны</h2>
      <span class="spacer"></span>
      <button class="link" onclick={() => (picking = false)}>Закрыть</button>
    </div>
    <p class="muted small">
      Списки сайтов и адресов в шаблонах (<code>geosite:…</code>, <code>geoip:…</code>) берутся из базы правил{#if geo}{' '}<b>{sourceName(geo, geo.source)}</b>{/if} и обновляются
      сами. Сменить базу: «Настройки → Базы geosite и geoip».
    </p>

    <h3>Готовые схемы</h3>
    <p class="muted small">
      Схема — несколько правил для всех устройств и «Всё остальное». Её правила встают в начало списка, ваши остаются ниже.
    </p>
    <div class="tpls schemes">
      {#each schemes as sc (sc.id)}
        {@const warn = schemeWarning(sc)}
        <div class="tpl">
          <strong>{sc.name}</strong>
          <span class="muted small">{sc.hint}</span>
          {#if warn}<span class="warn small">{warn}</span>{/if}
          <button class="use" disabled={editing !== null} onclick={() => useScheme(sc)}>Добавить к правилам</button>
        </div>
      {/each}
    </div>

    <h3>Отдельные правила</h3>
    <p class="muted small">
      Шаблон откроется как новое правило: выберите устройства (ни одного — все устройства сети) и сервер, затем нажмите «Готово».
    </p>
    {#each tplGroups as g (g)}
      <div class="group">{g}</div>
      <div class="tpls">
        {#each templates.filter((t) => t.group === g) as t (t.id)}
          {@const miss = missingLists(t.domains, geo)}
          <button class="tpl" disabled={editing !== null} onclick={() => fromTemplate(t)}>
            <strong>{t.name}</strong>
            <span class="muted small">{t.hint}</span>
            <code class="lists">{t.domains.join(' ')}</code>
            {#if miss}<span class="warn small">{miss}</span>{/if}
          </button>
        {/each}
      </div>
    {/each}
  </div>
{/if}

<div class="card">
  <div class="row head">
    <h2>Правила</h2>
    <span class="spacer"></span>
    <button disabled={editing !== null} onclick={openTemplates}>Шаблоны</button>
    <button class="primary" disabled={editing !== null} onclick={add}>Добавить правило</button>
  </div>
  {#if cfg.rules.length === 0}
    <p class="muted">Правил пока нет: всё идёт по «Всё остальное».</p>
  {:else}
    <ol class="list rules">
      {#each cfg.rules as r, i (i)}
        <li class:off={r.enabled === false}>
          {#if editing === i}
            <RuleEditor rule={r} {view} onsave={edited} oncancel={() => (editing = null)} />
          {:else}
            <div class="row">
              <span class="num">{i + 1}</span>
              <strong>{r.name || 'Без названия'}</strong>
              <span class="badge {r.action === 'direct' ? 'ok' : r.action === 'block' ? 'bad' : ''}">
                {actionText[r.action]}{r.action === 'tunnel' ? ': ' + serverName(r) : ''}
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
      <span class="auto-select">
        <TargetSelect {view} value={cfg.defaultProfile ?? ''} onchange={(v) => change(() => (cfg.defaultProfile = v || undefined))} />
      </span>
    {/if}
  </div>
  {#if cfg.defaultAction === 'tunnel'}
    <div class="fallbacks">
      <span class="muted small">Запасные серверы и группы</span>
      <FallbackList
        {view}
        list={cfg.defaultFallback ?? []}
        primary={cfg.defaultProfile ?? ''}
        onchange={(l) => change(() => (cfg.defaultFallback = l.length ? l : undefined))}
      />
    </div>
  {/if}
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
  .auto-select :global(select) {
    width: auto;
  }
  .fallbacks {
    margin-top: 12px;
  }
  .picker {
    border-color: var(--accent);
  }
  .picker h3 {
    margin: 16px 0 4px;
    font-size: 1rem;
  }
  .group {
    margin: 12px 0 6px;
    font-weight: 600;
    font-size: 0.9rem;
  }
  .tpls {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(min(220px, 100%), 1fr));
    gap: 8px;
    margin-top: 8px;
  }
  .tpls.schemes {
    grid-template-columns: repeat(auto-fill, minmax(min(280px, 100%), 1fr));
  }
  .tpl {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 4px;
    text-align: left;
    padding: 10px 12px;
    border: 1px solid var(--line);
    border-radius: 10px;
    background: var(--panel-2);
    min-width: 0;
  }
  .tpl .use {
    margin-top: auto;
  }
  .lists {
    color: var(--muted);
    font-size: 0.78rem;
    overflow-wrap: anywhere;
  }
  .warn {
    color: var(--warn);
  }
</style>
