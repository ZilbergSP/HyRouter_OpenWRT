<script lang="ts">
  import type { StateView } from './types';
  import { mainName } from './targets';

  let {
    view,
    value = $bindable(''),
    main = true,
    placeholder = '',
    exclude = [],
    onchange,
  }: {
    view: StateView;
    value?: string;
    main?: boolean;
    placeholder?: string;
    exclude?: string[];
    onchange?: (v: string) => void;
  } = $props();

  const servers = $derived(view.servers.filter((s) => !exclude.includes(s.id)));
  const groups = $derived(view.groups.groups.filter((g) => !exclude.includes(g.id)));
</script>

<select bind:value onchange={() => onchange?.(value)}>
  {#if main}<option value="">Основной: {mainName(view)}</option>{:else if placeholder}<option value="" disabled>{placeholder}</option>{/if}
  {#if groups.length > 0}
    <optgroup label="Группы">
      {#each groups as g (g.id)}
        <option value={g.id}>{g.name}</option>
      {/each}
    </optgroup>
  {/if}
  {#if servers.length > 0}
    <optgroup label="Серверы">
      {#each servers as s (s.id)}
        <option value={s.id}>{s.name}{s.missing ? ' (нет в подписке)' : ''}</option>
      {/each}
    </optgroup>
  {/if}
</select>
