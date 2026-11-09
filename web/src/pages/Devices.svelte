<script lang="ts">
  import { onMount } from 'svelte';
  import { api, errorText } from '../lib/api';
  import type { Device, Neighbour, StateView } from '../lib/types';

  let { view, onstate }: { view: StateView; onstate: (v: StateView) => void } = $props();

  function fresh(): Device[] {
    return $state.snapshot(view.devices) as Device[];
  }

  let devices = $state(fresh());
  let neighbours = $state<Neighbour[]>([]);
  let dirty = $state(false);
  let busy = $state(false);
  let error = $state('');
  let saved = $state(false);
  let form = $state({ name: '', mac: '', ip: '' });

  onMount(async () => {
    try {
      neighbours = await api.neighbours();
    } catch (e) {
      error = errorText(e);
    }
  });

  function newID(mac: string): string {
    const base = mac ? mac.toLowerCase().replace(/[^0-9a-f]/g, '') : '';
    let id = base || Math.random().toString(16).slice(2, 10);
    while (devices.some((d) => d.id === id)) id = base + '-' + Math.random().toString(16).slice(2, 6);
    return id;
  }

  function known(mac: string): boolean {
    return devices.some((d) => d.macs?.includes(mac));
  }

  function add(name: string, mac: string, ip: string) {
    const d: Device = { id: newID(mac), name: name || mac || ip };
    if (mac) d.macs = [mac.toLowerCase()];
    if (ip) d.addrs = [ip];
    devices.push(d);
    dirty = true;
    saved = false;
  }

  function addManual(e: SubmitEvent) {
    e.preventDefault();
    add(form.name.trim(), form.mac.trim(), form.ip.trim());
    form = { name: '', mac: '', ip: '' };
  }

  function remove(i: number) {
    const d = devices[i];
    if (!confirm(`Удалить устройство «${d.name}»? Правила, которые его называют, перестанут для него срабатывать.`)) return;
    devices.splice(i, 1);
    dirty = true;
    saved = false;
  }

  function rename(i: number, name: string) {
    devices[i].name = name;
    dirty = true;
    saved = false;
  }

  async function save() {
    busy = true;
    error = '';
    try {
      const r = await api.saveDevices($state.snapshot(devices) as Device[]);
      onstate(r.state);
      devices = $state.snapshot(r.state.devices) as Device[];
      dirty = false;
      saved = true;
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  function revert() {
    devices = fresh();
    dirty = false;
    error = '';
  }
</script>

<h1>Устройства</h1>
<p class="lead">
  Назовите устройства, чтобы выбирать их в правилах. Устройство узнаётся по MAC-адресу, а если его нет — по IP. У
  телефонов со «случайным MAC» закрепите в их настройках постоянный адрес для домашней сети.
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
{#if saved}<div class="notice ok">Устройства сохранены.</div>{/if}

<div class="card">
  <h2>Ваши устройства</h2>
  {#if devices.length === 0}
    <p class="muted">Пока нет ни одного. Добавьте из списка ниже или вручную.</p>
  {:else}
    <ul class="list">
      {#each devices as d, i (d.id)}
        <li class="row">
          <input class="name" value={d.name} onchange={(e) => rename(i, e.currentTarget.value.trim())} aria-label="Имя устройства" />
          <span class="muted small addrs">{[...(d.macs ?? []), ...(d.addrs ?? [])].join(', ')}</span>
          <span class="spacer"></span>
          <button class="link danger" onclick={() => remove(i)}>Удалить</button>
        </li>
      {/each}
    </ul>
  {/if}
</div>

<div class="card">
  <h2>Сейчас в сети</h2>
  <p class="muted small">Устройства, которым роутер выдал адрес по DHCP.</p>
  {#if neighbours.length === 0}
    <p class="muted">Список пуст или недоступен.</p>
  {:else}
    <ul class="list">
      {#each neighbours as n (n.mac + n.ip)}
        <li class="row">
          <strong>{n.name || 'без имени'}</strong>
          <span class="muted small">{n.ip} · {n.mac}</span>
          <span class="spacer"></span>
          {#if known(n.mac)}
            <span class="badge ok">добавлено</span>
          {:else}
            <button class="link" onclick={() => add(n.name, n.mac, '')}>Добавить</button>
          {/if}
        </li>
      {/each}
    </ul>
  {/if}
</div>

<form class="card" onsubmit={addManual}>
  <h2>Добавить вручную</h2>
  <div class="three">
    <label class="field"><span>Имя</span><input bind:value={form.name} placeholder="Телевизор" /></label>
    <label class="field"><span>MAC-адрес</span><input bind:value={form.mac} placeholder="aa:bb:cc:dd:ee:ff" /></label>
    <label class="field"><span>или IP-адрес / подсеть</span><input bind:value={form.ip} placeholder="192.168.1.20" /></label>
  </div>
  <button type="submit" disabled={!form.mac.trim() && !form.ip.trim()}>Добавить</button>
</form>

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
  .name {
    width: 220px;
  }
  .addrs {
    word-break: break-all;
  }
  .three {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 12px;
  }
  @media (max-width: 760px) {
    .three {
      grid-template-columns: 1fr;
    }
    .name {
      width: 100%;
    }
  }
</style>
