<script lang="ts">
  import type { Action, Rule, StateView } from '../lib/types';
  import TargetSelect from '../lib/TargetSelect.svelte';
  import FallbackList from '../lib/FallbackList.svelte';

  let {
    rule,
    view,
    onsave,
    oncancel,
  }: {
    rule: Rule;
    view: StateView;
    onsave: (r: Rule) => void;
    oncancel: () => void;
  } = $props();

  const devices = $derived(view.devices);

  function initial() {
    const r = $state.snapshot(rule) as Rule;
    const devs = r.devices ?? [];
    return {
      name: r.name ?? '',
      picked: devs.filter((d) => d.startsWith('dev:')).map((d) => d.slice(4)),
      other: devs.filter((d) => !d.startsWith('dev:')).join(', '),
      sites: (r.domains ?? []).join('\n'),
      protocol: r.protocol ?? '',
      ports: r.ports ?? '',
      action: (r.action ?? 'tunnel') as Action,
      profile: r.profile ?? '',
      fallback: r.fallback ?? [],
      enabled: r.enabled !== false,
    };
  }

  let f = $state(initial());

  function toggleDevice(id: string, on: boolean) {
    f.picked = on ? [...f.picked, id] : f.picked.filter((x) => x !== id);
  }

  function save(e: SubmitEvent) {
    e.preventDefault();
    const devs = [
      ...f.picked.map((id) => 'dev:' + id),
      ...f.other
        .split(/[\s,;]+/)
        .map((s) => s.trim())
        .filter(Boolean),
    ];
    const domains = f.sites
      .split('\n')
      .map((s) => s.trim())
      .filter(Boolean);
    const out: Rule = { name: f.name.trim(), action: f.action };
    if (rule.id) out.id = rule.id;
    if (devs.length) out.devices = devs;
    if (domains.length) out.domains = domains;
    if (f.protocol) out.protocol = f.protocol;
    if (f.ports.trim()) out.ports = f.ports.trim();
    if (f.action === 'tunnel' && f.profile) out.profile = f.profile;
    if (f.action === 'tunnel' && f.fallback.length) out.fallback = [...f.fallback];
    if (!f.enabled) out.enabled = false;
    onsave(out);
  }
</script>

<form class="card editor" onsubmit={save}>
  <h2>{rule.name ? `Правило «${rule.name}»` : 'Новое правило'}</h2>

  <label class="field">
    <span>Название</span>
    <input bind:value={f.name} placeholder="Например, Телевизор через VPN" />
  </label>

  <div class="field">
    <span class="label">Устройства (никакое не выбрано — все устройства сети)</span>
    {#if devices.length > 0}
      <div class="chips">
        {#each devices as d (d.id)}
          <label class="chip">
            <input type="checkbox" checked={f.picked.includes(d.id)} onchange={(e) => toggleDevice(d.id, e.currentTarget.checked)} />
            {d.name || d.id}
          </label>
        {/each}
      </div>
    {:else}
      <p class="muted small">Сохранённых устройств нет: добавьте их в разделе «Устройства» или укажите адрес ниже.</p>
    {/if}
    <input bind:value={f.other} placeholder="Другие: MAC или IP через запятую, например aa:bb:cc:dd:ee:ff, 192.168.1.20" />
  </div>

  <label class="field">
    <span>Сайты и адреса, по одному в строке (пусто — любые)</span>
    <textarea rows="5" bind:value={f.sites} placeholder={'.youtube.com — сайт и его поддомены\nkinopoisk.ru — только этот адрес\n203.0.113.0/24 — сеть\ngeosite:ru-blocked — категория сайтов\ngeoip:ru — адреса страны'}></textarea>
  </label>

  <div class="two">
    <label class="field">
      <span>Протокол</span>
      <select bind:value={f.protocol}>
        <option value="">любой</option>
        <option value="tcp">TCP</option>
        <option value="udp">UDP</option>
      </select>
    </label>
    <label class="field">
      <span>Порты (пусто — любые)</span>
      <input bind:value={f.ports} placeholder="443, 8000-8100" />
    </label>
  </div>

  <div class="field">
    <span class="label">Куда</span>
    <div class="row">
      <label class="check"><input type="radio" bind:group={f.action} value="tunnel" /> Через VPN</label>
      <label class="check"><input type="radio" bind:group={f.action} value="direct" /> Напрямую</label>
      <label class="check"><input type="radio" bind:group={f.action} value="block" /> Блокировать</label>
    </div>
  </div>

  {#if f.action === 'tunnel'}
    <label class="field">
      <span>Сервер или группа</span>
      <TargetSelect {view} bind:value={f.profile} />
    </label>
    <div class="field">
      <span class="label">Запасные: если основной не может пропустить соединение, берётся первый доступный из списка</span>
      <FallbackList {view} bind:list={f.fallback} primary={f.profile} />
    </div>
  {/if}

  <label class="check field"><input type="checkbox" bind:checked={f.enabled} /> Правило включено</label>

  <div class="row">
    <button class="primary" type="submit">Готово</button>
    <button type="button" onclick={oncancel}>Отмена</button>
  </div>
</form>

<style>
  .editor {
    border-color: var(--accent);
  }
  .label {
    display: block;
    font-size: 0.86rem;
    color: var(--muted);
    margin-bottom: 6px;
  }
  .chips {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin-bottom: 8px;
  }
  .chip {
    display: flex;
    align-items: center;
    gap: 6px;
    border: 1px solid var(--line);
    border-radius: 999px;
    padding: 4px 12px 4px 8px;
    background: var(--panel-2);
    cursor: pointer;
  }
  .two {
    display: grid;
    grid-template-columns: 1fr 2fr;
    gap: 12px;
  }
  textarea {
    font-family: ui-monospace, 'SF Mono', Menlo, Consolas, monospace;
    font-size: 0.9rem;
  }
</style>
