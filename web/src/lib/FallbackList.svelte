<script lang="ts">
  import type { StateView } from './types';
  import { targetName } from './targets';
  import TargetSelect from './TargetSelect.svelte';

  // Fallbacks: servers or groups tried in order when the primary one
  // cannot carry a connection.
  let {
    view,
    list = $bindable([]),
    primary,
    onchange,
  }: {
    view: StateView;
    list?: string[];
    primary: string;
    onchange?: (list: string[]) => void;
  } = $props();

  let adding = $state('');

  const options = $derived([...view.servers.map((s) => s.id), ...view.groups.groups.map((g) => g.id)]);
  const left = $derived(options.filter((id) => id !== (primary || view.settings.main) && !list.includes(id)));

  function set(next: string[]) {
    list = next;
    onchange?.(next);
  }

  function add() {
    if (!adding) return;
    set([...list, adding]);
    adding = '';
  }

  function move(i: number, d: number) {
    const next = [...list];
    [next[i], next[i + d]] = [next[i + d], next[i]];
    set(next);
  }
</script>

<div class="fallback">
  {#if list.length > 0}
    <ol>
      {#each list as id, i (id)}
        <li>
          <span>{id ? targetName(view, id) : 'основной'}</span>
          <span class="spacer"></span>
          <button type="button" class="link" aria-label="Выше" disabled={i === 0} onclick={() => move(i, -1)}>↑</button>
          <button type="button" class="link" aria-label="Ниже" disabled={i === list.length - 1} onclick={() => move(i, 1)}>↓</button>
          <button type="button" class="link danger" onclick={() => set(list.filter((x) => x !== id))}>Убрать</button>
        </li>
      {/each}
    </ol>
  {/if}
  {#if left.length > 0}
    <div class="row">
      <TargetSelect {view} bind:value={adding} main={false} placeholder="Выберите сервер или группу" exclude={options.filter((id) => !left.includes(id))} />
      <button type="button" disabled={!adding} onclick={add}>Добавить запасной</button>
    </div>
  {/if}
</div>

<style>
  ol {
    margin: 0 0 8px;
    padding-left: 22px;
  }
  li {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 3px 0;
  }
  .fallback :global(select) {
    width: auto;
    min-width: 200px;
  }
</style>
