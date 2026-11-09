<script lang="ts">
  import { onMount } from 'svelte';
  import { api, errorText } from '../lib/api';
  import type { GeoStatus, StateView } from '../lib/types';

  let { view, onstate }: { view: StateView; onstate: (v: StateView) => void } = $props();

  let geo = $state<GeoStatus | null>(null);
  let error = $state('');
  let busy = $state(false);

  async function load() {
    try {
      geo = await api.geo();
    } catch (e) {
      error = errorText(e);
    }
  }

  onMount(() => {
    load();
    const t = setInterval(() => {
      if (geo?.busy) load();
    }, 3000);
    return () => clearInterval(t);
  });

  async function setSource(source: string, auto: boolean) {
    busy = true;
    error = '';
    try {
      const r = await api.saveGeo({ source, auto });
      onstate(r.state);
      geo = r.geo;
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  async function update() {
    error = '';
    try {
      geo = await api.updateGeo();
    } catch (e) {
      error = errorText(e);
    }
  }

  function when(t?: string): string {
    if (!t) return 'никогда';
    return new Date(t).toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'short' });
  }
</script>

<div class="card">
  <h2>Базы geosite и geoip</h2>
  <p class="muted small">
    В правилах можно указать целую категорию сайтов или адресов: <code>geosite:youtube</code>, <code>geosite:ru-blocked</code>,
    <code>geoip:ru</code>. HyRouter скачивает базу во временную память, сохраняет на роутере только категории из ваших правил
    и сразу освобождает память.{view.lite ? ' На слабом роутере выбирайте источник поменьше: v2fly.' : ''}
  </p>
  {#if geo}
    <div class="two">
      <label class="field">
        <span>Источник</span>
        <select value={geo.source} disabled={busy} onchange={(e) => setSource(e.currentTarget.value, geo?.auto ?? true)}>
          {#each geo.sources as s (s.id)}
            <option value={s.id}>{s.name} ({s.size})</option>
          {/each}
        </select>
      </label>
      <label class="check field auto">
        <input type="checkbox" checked={geo.auto} disabled={busy} onchange={(e) => setSource(geo?.source ?? '', e.currentTarget.checked)} />
        Обновлять раз в сутки
      </label>
    </div>
    <p class="muted small">{geo.sources.find((s) => s.id === geo?.source)?.description}</p>
    <div class="small">
      Обновлена: {when(geo.updated)}.
      {#if geo.sites.length + geo.ips.length > 0}
        На роутере: {[...geo.sites.map((n) => 'geosite:' + n), ...geo.ips.map((n) => 'geoip:' + n)].join(', ')}.
      {:else}
        Правила пока не используют категории.
      {/if}
    </div>
    {#if geo.missing.length > 0}
      <div class="notice">
        Ещё не скачаны: {geo.missing.join(', ')}. Пока их нет, эти пункты правил ничего не выбирают; HyRouter скачает их сам.
      </div>
    {/if}
    {#if geo.error}<div class="notice bad">Последнее обновление не удалось: {geo.error}</div>{/if}
    <button disabled={geo.busy} onclick={update}>{geo.busy ? 'Скачиваю…' : 'Обновить сейчас'}</button>
  {/if}
  {#if error}<div class="notice bad">{error}</div>{/if}
</div>

<style>
  .two {
    display: grid;
    grid-template-columns: 2fr 1fr;
    gap: 12px;
    align-items: end;
  }
  .auto {
    margin-bottom: 14px;
  }
  @media (max-width: 640px) {
    .two {
      grid-template-columns: 1fr;
    }
  }
</style>
