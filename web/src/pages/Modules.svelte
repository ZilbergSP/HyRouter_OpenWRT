<script lang="ts">
  import { onMount } from 'svelte';
  import { api, errorText } from '../lib/api';
  import type { ModuleView } from '../lib/types';

  let mods = $state<ModuleView[] | null>(null);
  let error = $state('');

  async function load() {
    try {
      mods = await api.modules();
    } catch (e) {
      error = errorText(e);
    }
  }

  onMount(() => {
    load();
    const t = setInterval(() => {
      if (mods?.some((m) => m.busy)) load();
    }, 1500);
    return () => clearInterval(t);
  });

  async function install(m: ModuleView) {
    error = '';
    try {
      mods = await api.installModule(m.id);
    } catch (e) {
      error = errorText(e);
    }
  }

  async function remove(m: ModuleView) {
    const lost = m.servers ? `\n\nСерверы VLESS (${m.servers}) перестанут работать.` : '';
    if (!confirm(`Удалить модуль ${m.title}?${lost}`)) return;
    error = '';
    try {
      mods = await api.removeModule(m.id);
    } catch (e) {
      error = errorText(e);
    }
  }

  const mb = (n: number) => `${Math.max(1, Math.round(n / (1 << 20)))} МБ`;
</script>

<div class="card">
  <h2>Модули</h2>
  <p class="muted small">
    Hysteria 2 встроена в HyRouter и работает сразу. Остальное скачивается по кнопке, только если нужно, и проверяется по
    контрольной сумме.
  </p>
  {#if mods}
    {#each mods as m (m.id)}
      <div class="mod">
        <div class="row">
          <strong>{m.title}</strong>
          {#if m.installed}<span class="badge ok">установлен</span>{/if}
          {#if m.installed && m.ram}<span class="badge warn">во временном хранилище</span>{/if}
          <span class="spacer"></span>
          {#if !m.available}
            <span class="muted small">нет в HyRouter Lite</span>
          {:else if m.busy}
            <span class="small">Скачиваю и проверяю…</span>
          {:else if m.installed}
            <button class="link danger" onclick={() => remove(m)}>Удалить</button>
          {:else}
            <button class="primary" onclick={() => install(m)}>Скачать</button>
          {/if}
        </div>
        <p class="muted small">{m.hint}</p>
        {#if m.installed}
          <p class="small">
            Версия {m.version}{m.size ? `, ${mb(m.size)}` : ''}{m.ram
              ? '. На флеше не хватило места: после перезагрузки роутера модуль скачается заново'
              : ''}.
          </p>
        {:else if m.available && m.servers > 0}
          <div class="notice">Серверов VLESS в настройках: {m.servers}. Без модуля они не работают.</div>
        {/if}
        {#if m.error}<div class="notice bad">Не скачался: {m.error}</div>{/if}
      </div>
    {/each}
  {/if}
  {#if error}<div class="notice bad">{error}</div>{/if}
</div>

<style>
  .mod {
    border: 1px solid var(--line);
    border-radius: 10px;
    padding: 10px 12px;
    background: var(--panel-2);
    margin: 8px 0;
  }
  .mod p {
    margin: 6px 0 0;
  }
</style>
