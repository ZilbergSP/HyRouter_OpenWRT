<script lang="ts">
  import { onMount } from 'svelte';
  import { api, errorText } from '../lib/api';
  import type { LogEntry } from '../lib/types';

  let entries = $state<LogEntry[]>([]);
  let error = $state('');
  let follow = $state(true);
  let box: HTMLDivElement | undefined = $state();

  const max = 2000;

  async function poll() {
    try {
      const last = entries.length ? entries[entries.length - 1].seq : 0;
      const more = await api.log(last);
      if (more.length) {
        entries = [...entries, ...more].slice(-max);
        if (follow && box) {
          const b = box;
          requestAnimationFrame(() => (b.scrollTop = b.scrollHeight));
        }
      }
      error = '';
    } catch (e) {
      error = errorText(e);
    }
  }

  onMount(() => {
    poll();
    const t = setInterval(poll, 2000);
    return () => clearInterval(t);
  });

  function time(s: string): string {
    const d = new Date(s);
    return isNaN(d.getTime()) ? '' : d.toLocaleTimeString('ru-RU');
  }
</script>

<h1>Журнал</h1>
<p class="lead">События hyrouterd. Пароли серверов в журнал не попадают.</p>

{#if error}<div class="notice bad">{error}</div>{/if}

<div class="card">
  <div class="row bar">
    <label class="check small"><input type="checkbox" bind:checked={follow} /> прокручивать к новым</label>
    <span class="spacer"></span>
    <span class="muted small">{entries.length} записей</span>
  </div>
  <div class="log" bind:this={box}>
    {#each entries as e (e.seq)}
      <div class="line {e.level}">
        <span class="t">{time(e.time)}</span>
        <span class="lv">{e.level}</span>
        <span class="m">{e.msg}</span>
      </div>
    {:else}
      <div class="muted">Записей пока нет.</div>
    {/each}
  </div>
</div>

<style>
  .bar {
    margin-bottom: 10px;
  }
  .log {
    height: 60vh;
    overflow: auto;
    font-family: ui-monospace, 'SF Mono', Menlo, Consolas, monospace;
    font-size: 0.82rem;
    background: var(--panel-2);
    border: 1px solid var(--line);
    border-radius: 9px;
    padding: 10px;
  }
  .line {
    display: grid;
    grid-template-columns: 70px 46px 1fr;
    gap: 8px;
    padding: 1px 0;
  }
  .t,
  .lv {
    color: var(--muted);
  }
  .m {
    white-space: pre-wrap;
    word-break: break-word;
  }
  .warn .lv,
  .warn .m {
    color: var(--warn);
  }
  .error .lv,
  .error .m {
    color: var(--bad);
  }
</style>
