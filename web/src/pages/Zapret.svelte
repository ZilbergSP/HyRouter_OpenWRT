<script lang="ts">
  import { onMount } from 'svelte';
  import { api, errorText } from '../lib/api';
  import TargetSelect from '../lib/TargetSelect.svelte';
  import type { StateView, ZapretView } from '../lib/types';

  let { view, onstate }: { view: StateView; onstate: (v: StateView) => void } = $props();

  let z = $state<ZapretView | null>(null);
  let f = $state<{
    enabled: boolean;
    targets: string[];
    sites: string;
    methods: Record<string, string>;
    via: Record<string, string>;
    autoHeal: boolean;
  } | null>(null);
  let busy = $state(false);
  let error = $state('');
  let saved = $state(false);
  let showLog = $state(false);

  function fill(v: ZapretView) {
    const s = v.settings;
    f = {
      enabled: s.enabled,
      targets: [...(s.targets ?? [])],
      sites: (s.sites ?? []).join('\n'),
      methods: { ...(s.methods ?? {}) },
      via: { ...(s.via ?? {}) },
      autoHeal: s.autoHeal !== false,
    };
  }

  async function load(refill = false) {
    try {
      z = await api.zapret();
      if (refill || !f) fill(z);
    } catch (e) {
      error = errorText(e);
    }
  }

  onMount(() => {
    load(true);
    const t = setInterval(() => load(false), 2500);
    return () => clearInterval(t);
  });

  function toggle(t: string, on: boolean) {
    if (!f) return;
    f.targets = on ? [...f.targets, t] : f.targets.filter((x) => x !== t);
    saved = false;
  }

  async function save(e: SubmitEvent) {
    e.preventDefault();
    if (!f) return;
    busy = true;
    error = '';
    saved = false;
    try {
      const r = await api.saveZapret({
        enabled: f.enabled,
        targets: f.targets,
        sites: f.sites
          .split('\n')
          .map((s) => s.trim())
          .filter(Boolean),
        methods: Object.fromEntries(Object.entries(f.methods).filter(([, m]) => m)),
        via: f.via,
        autoHeal: f.autoHeal,
      });
      onstate(r.state);
      z = r.zapret;
      fill(r.zapret);
      saved = true;
    } catch (err) {
      error = errorText(err);
    } finally {
      busy = false;
    }
  }

  async function pick() {
    error = '';
    try {
      z = await api.zapretPick();
    } catch (err) {
      error = errorText(err);
    }
  }

  async function cancel() {
    try {
      z = await api.zapretPickCancel();
    } catch (err) {
      error = errorText(err);
    }
  }

  function methodName(id: string): string {
    if (id === 'none') return 'не нужен: открывается и так';
    if (!id) return 'ничего не помогло';
    return z?.methods.find((m) => m.id === id)?.name ?? 'свой вариант';
  }

  const stateText: Record<string, string> = { off: 'остановлен', running: 'работает', error: 'ошибка' };
</script>

<h1>Обход DPI</h1>
<p class="lead">
  YouTube, Discord и свои сайты открываются напрямую, без VPN: nfqws2 из zapret2 меняет первые пакеты соединений так, что
  блокировка провайдера их не узнаёт. Работает для всех устройств сети, пока HyRouter включён.
</p>

{#if z && !z.available}
  <div class="notice bad">В этой сборке нет nfqws2: обход DPI недоступен.</div>
{/if}
{#if z?.offload}
  <div class="notice">
    В настройках межсетевого экрана включено ускорение (flow offloading): часть соединений может пройти мимо обхода.
    Если сайты открываются через раз, выключите его: Network → Firewall → Routing/NAT Offloading.
  </div>
{/if}

{#if f && z}
  <form class="card" onsubmit={save}>
    <label class="check field"><input type="checkbox" bind:checked={f.enabled} /> <strong>Обход DPI включён</strong></label>
    <div class="targets">
      {#each z.targets as t (t.target)}
        <div class="target">
          <label class="check"
            ><input type="checkbox" checked={f.targets.includes(t.target)} onchange={(e) => toggle(t.target, e.currentTarget.checked)} />
            <strong>{t.name}</strong></label
          >
          {#if f.targets.includes(t.target)}
            <div class="row small">
              <select class="auto" bind:value={f.methods[t.target]}>
                <option value="">Подбирать автоматически</option>
                <option value="vpn">Пустить через VPN</option>
                <option value="none">Не обходить</option>
                {#each z.methods as m (m.id)}<option value={m.id}>{m.name}</option>{/each}
              </select>
              {#if f.methods[t.target] === 'vpn'}
                <span class="via">
                  <select class="auto" bind:value={f.via[t.target]}>
                    <option value="">Основной сервер</option>
                    <option value="rules">По вашим правилам</option>
                    {#each view.groups.groups as g (g.id)}<option value={g.id}>Группа «{g.name}»</option>{/each}
                    {#each view.servers.filter((s) => !s.source) as s (s.id)}<option value={s.id}>{s.name}</option>{/each}
                  </select>
                </span>
              {/if}
            </div>
            {#if t.using}<div class="muted small">Сейчас: {t.using}</div>{/if}
          {/if}
        </div>
      {/each}
    </div>
    {#if f.targets.includes('sites')}
      <label class="field">
        <span>Свои сайты: имена, внешние адреса или сети, по одному в строке</span>
        <textarea rows="4" bind:value={f.sites} placeholder={'rutracker.org\n104.16.0.0/13'}></textarea>
      </label>
    {/if}
    <label class="check field">
      <input type="checkbox" bind:checked={f.autoHeal} /> Следить самому: раз в 10 минут проверять сервисы и подбирать методы
      заново, если они перестали открываться
    </label>
    {#if error}<div class="notice bad">{error}</div>{/if}
    {#if saved}<div class="notice ok">Сохранено. Правила «Обход DPI: …» наверху списка правил держат эти сервисы на прямом пути.</div>{/if}
    <button class="primary" type="submit" disabled={busy}>Сохранить</button>
  </form>

  <div class="card">
    <div class="row">
      <h2>Подбор методов</h2>
      <span class="spacer"></span>
      {#if z.pick?.running}
        <button onclick={cancel}>Остановить</button>
      {:else}
        <button class="primary" disabled={!z.routing || !z.available || !z.settings.enabled} onclick={pick}>Подобрать автоматически</button>
      {/if}
    </div>
    <p class="muted small">
      HyRouter проверяет сервисы с самого роутера: сначала без обхода, затем каждым методом отдельно, и запоминает
      лучшие для этой сети{z.network ? ` (шлюз ${z.network})` : ''}. Обход сети во время подбора продолжает работать.
    </p>
    {#if !z.routing}<p class="muted small">Подбор доступен, когда HyRouter включён.</p>{/if}
    {#if z.pick}
      <div class="small">
        {#if z.pick.running}
          <div>{z.pick.step}</div>
          <div class="bar"><span style="width: {Math.min(100, (z.pick.done / Math.max(1, z.pick.total)) * 100)}%"></span></div>
        {:else if z.pick.error}
          <div class="notice bad">Подбор не завершился: {z.pick.error}</div>
        {:else}
          <div>Подбор завершён{z.pick.auto ? ` автоматически (${z.pick.why})` : ''}. Проверено вариантов: {z.pick.tried}.</div>
        {/if}
        <ul>
          {#each Object.entries(z.pick.results ?? {}) as [t, m] (t)}
            <li><strong>{z.targets.find((x) => x.target === t)?.name ?? t}</strong>: {methodName(m)}</li>
          {/each}
          {#each Object.entries(z.pick.diagnosis ?? {}) as [t, d] (t)}
            {#if !(z.pick.results ?? {})[t] || !d.bypass}
              <li class="muted">
                {z.targets.find((x) => x.target === t)?.name ?? t}: {d.text}{d.detail ? ` (${d.detail})` : ''}{d.bypass
                  ? ''
                  : ' — обход тут не поможет, только VPN'}
              </li>
            {/if}
          {/each}
        </ul>
        {#if z.pick.skipped?.length}
          <div class="muted">Не проверялись (не открываются и без блокировки): {z.pick.skipped.join('; ')}</div>
        {/if}
      </div>
    {/if}
    {#if z.healNote}<p class="small">Самопроверка: {z.healNote}</p>{/if}
  </div>

  <div class="card">
    <div class="row">
      <h2>nfqws2</h2>
      <span class="badge {z.status.state === 'running' ? 'ok' : z.status.state === 'error' ? 'bad' : ''}"
        >{stateText[z.status.state] ?? z.status.state}</span
      >
      <span class="spacer"></span>
      <button class="link" onclick={() => (showLog = !showLog)}>{showLog ? 'Скрыть' : 'Журнал и командная строка'}</button>
    </div>
    {#if z.error}<p class="small err">{z.error}</p>{/if}
    {#if z.status.error}<p class="small err">{z.status.error}</p>{/if}
    <p class="muted small">WAN: {z.wan.length ? z.wan.join(', ') : 'не найден'}</p>
    {#if showLog}
      {#if z.commandLine}<pre>{z.commandLine}</pre>{/if}
      <pre>{z.status.lines.join('\n') || 'Пусто'}</pre>
    {/if}
  </div>
{/if}

<style>
  .targets {
    display: grid;
    gap: 10px;
    margin: 10px 0;
  }
  .target {
    border: 1px solid var(--line);
    border-radius: 10px;
    padding: 10px 12px;
    background: var(--panel-2);
    display: grid;
    gap: 6px;
  }
  .auto {
    width: auto;
  }
  .bar {
    height: 6px;
    border-radius: 3px;
    background: var(--panel-2);
    border: 1px solid var(--line);
    margin: 6px 0;
    overflow: hidden;
  }
  .bar span {
    display: block;
    height: 100%;
    background: var(--accent);
  }
  pre {
    white-space: pre-wrap;
    word-break: break-all;
    font-size: 0.8rem;
    background: var(--panel-2);
    border: 1px solid var(--line);
    border-radius: 8px;
    padding: 8px;
    max-height: 300px;
    overflow: auto;
  }
  .err {
    color: var(--bad);
  }
  h2 {
    margin: 0;
  }
</style>
