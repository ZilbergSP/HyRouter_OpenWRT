<script lang="ts">
  import { api, errorText } from '../lib/api';
  import type { StateView } from '../lib/types';

  let {
    view,
    version,
    onstate,
    onlogout,
  }: { view: StateView; version: string; onstate: (v: StateView) => void; onlogout: () => void } = $props();

  function initial() {
    const s = $state.snapshot(view.settings);
    return {
      lan: s.lan.join(', '),
      dnsByRules: s.dns.byRules,
      dnsTunnel: s.dns.tunnel?.preset ?? '',
    };
  }

  let f = $state(initial());
  let busy = $state(false);
  let error = $state('');
  let saved = $state(false);

  async function save(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    error = '';
    saved = false;
    try {
      const lan = f.lan
        .split(/[\s,;]+/)
        .map((s) => s.trim())
        .filter(Boolean);
      const r = await api.saveSettings({ lan, dnsByRules: f.dnsByRules, dnsTunnel: f.dnsTunnel });
      onstate(r.state);
      saved = true;
    } catch (err) {
      error = errorText(err);
    } finally {
      busy = false;
    }
  }
</script>

<h1>Настройки</h1>
<p class="lead">{view.edition}, версия {version}.</p>

<form class="card" onsubmit={save}>
  <h2>Сеть</h2>
  <label class="field">
    <span>Интерфейсы LAN, трафик которых решает HyRouter</span>
    <input bind:value={f.lan} placeholder="br-lan" />
  </label>

  <h2 class="gap">DNS</h2>
  <label class="check field">
    <input type="checkbox" bind:checked={f.dnsByRules} />
    Имена сайтов «через VPN» узнавать через VPN
  </label>
  <p class="muted small">
    Так провайдер не видит, какие сайты из правил «через VPN» открываются, и не может подменить их адреса. Остальные имена
    разрешает dnsmasq роутера, как раньше.
  </p>
  {#if f.dnsByRules}
    <label class="field">
      <span>DNS-сервер для имён «через VPN»</span>
      <select bind:value={f.dnsTunnel}>
        <option value="">По умолчанию (Cloudflare)</option>
        {#each view.dnsPresets as p (p.id)}
          <option value={p.id}>{p.name}</option>
        {/each}
      </select>
    </label>
  {/if}

  {#if error}<div class="notice bad">{error}</div>{/if}
  {#if saved}<div class="notice ok">Настройки сохранены.</div>{/if}
  <button class="primary" type="submit" disabled={busy}>{busy ? 'Сохраняю…' : 'Сохранить'}</button>
</form>

<div class="card">
  <h2>Порты</h2>
  <p class="muted small">
    relay: {view.settings.tunnelPort} и {view.settings.namePort}, DNS: {view.settings.dnsPort},
    веб-интерфейс: {view.settings.webPort}. Их можно изменить в <code>/etc/hyrouter/settings.json</code>.
  </p>
</div>

<div class="card row">
  <div>
    <strong>Выход</strong>
    <div class="muted small">Сессия живёт сутки; выход завершает её сразу.</div>
  </div>
  <span class="spacer"></span>
  <button onclick={onlogout}>Выйти</button>
</div>

<style>
  .gap {
    margin-top: 18px;
  }
</style>
