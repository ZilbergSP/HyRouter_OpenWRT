<script lang="ts">
  import { onMount } from 'svelte';
  import { api, ApiError } from './lib/api';
  import type { StateView, Status } from './lib/types';
  import Login from './pages/Login.svelte';
  import Home from './pages/Home.svelte';
  import Servers from './pages/Servers.svelte';
  import Rules from './pages/Rules.svelte';
  import Devices from './pages/Devices.svelte';
  import Log from './pages/Log.svelte';
  import Settings from './pages/Settings.svelte';

  const pages = [
    { path: '/', title: 'Главная' },
    { path: '/servers', title: 'Серверы' },
    { path: '/rules', title: 'Правила' },
    { path: '/devices', title: 'Устройства' },
    { path: '/log', title: 'Журнал' },
    { path: '/settings', title: 'Настройки' },
  ];

  let ready = $state(false);
  let loggedIn = $state(false);
  let version = $state('');
  let view = $state<StateView | null>(null);
  let status = $state<Status | null>(null);
  let route = $state(currentRoute());
  let loadError = $state('');

  function currentRoute(): string {
    const r = location.hash.replace(/^#/, '') || '/';
    return pages.some((p) => p.path === r) ? r : '/';
  }

  async function load() {
    try {
      view = await api.state();
      status = (await api.status()).status;
      loadError = '';
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) loggedIn = false;
      else loadError = e instanceof Error ? e.message : String(e);
    }
  }

  async function loggedInNow() {
    loggedIn = true;
    await load();
  }

  async function logout() {
    try {
      await api.logout();
    } finally {
      loggedIn = false;
      view = null;
      status = null;
    }
  }

  onMount(() => {
    const onHash = () => (route = currentRoute());
    window.addEventListener('hashchange', onHash);
    (async () => {
      try {
        const s = await api.session();
        version = s.version;
        loggedIn = s.loggedIn;
        if (loggedIn) await load();
      } catch (e) {
        loadError = e instanceof Error ? e.message : String(e);
      }
      ready = true;
    })();
    return () => window.removeEventListener('hashchange', onHash);
  });

  $effect(() => {
    if (!loggedIn) return;
    const t = setInterval(async () => {
      try {
        status = (await api.status()).status;
      } catch (e) {
        if (e instanceof ApiError && e.status === 401) loggedIn = false;
      }
    }, 4000);
    return () => clearInterval(t);
  });
</script>

{#if !ready}
  <div class="center muted">Загрузка…</div>
{:else if !loggedIn}
  <Login {version} onlogin={loggedInNow} />
{:else}
  <div class="layout">
    <aside>
      <div class="brand">
        <img src="/favicon.svg" alt="" width="28" height="28" />
        <div>
          <div class="name">HyRouter</div>
          {#if view?.lite}<span class="badge">Lite</span>{/if}
        </div>
      </div>
      <nav>
        {#each pages as p (p.path)}
          <a href={'#' + p.path} class:active={route === p.path}>{p.title}</a>
        {/each}
      </nav>
      <div class="foot">
        {#if status}
          <span class="dot" class:connected={status.running}></span>{status.running ? 'Работает' : 'Выключен'}
        {/if}
        <div class="muted small">версия {version}</div>
      </div>
    </aside>
    <main>
      {#if loadError}
        <div class="notice bad">{loadError}</div>
      {/if}
      {#if view && status}
        {#if route === '/'}
          <Home {view} {status} onstatus={(s) => (status = s)} />
        {:else if route === '/servers'}
          <Servers {view} {status} onstate={(v) => (view = v)} />
        {:else if route === '/rules'}
          <Rules {view} onstate={(v) => (view = v)} />
        {:else if route === '/devices'}
          <Devices {view} onstate={(v) => (view = v)} />
        {:else if route === '/log'}
          <Log />
        {:else if route === '/settings'}
          <Settings {view} {version} onstate={(v) => (view = v)} onlogout={logout} />
        {/if}
      {/if}
    </main>
  </div>
{/if}

<style>
  .center {
    display: grid;
    place-items: center;
    min-height: 100vh;
  }
  .layout {
    display: grid;
    grid-template-columns: 220px 1fr;
    min-height: 100vh;
  }
  aside {
    background: var(--panel);
    border-right: 1px solid var(--line);
    padding: 20px 14px;
    display: flex;
    flex-direction: column;
    gap: 18px;
    position: sticky;
    top: 0;
    height: 100vh;
  }
  .brand {
    display: flex;
    gap: 10px;
    align-items: center;
    padding: 0 6px;
  }
  .name {
    font-weight: 700;
    font-size: 1.1rem;
  }
  nav {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  nav a {
    color: var(--text);
    text-decoration: none;
    padding: 8px 10px;
    border-radius: 9px;
  }
  nav a:hover {
    background: var(--panel-2);
  }
  nav a.active {
    background: var(--accent-soft);
    color: var(--accent);
    font-weight: 600;
  }
  .foot {
    margin-top: auto;
    padding: 0 6px;
  }
  main {
    padding: 28px 32px;
    max-width: 980px;
    width: 100%;
  }
  @media (max-width: 760px) {
    .layout {
      grid-template-columns: 1fr;
    }
    aside {
      position: static;
      height: auto;
      border-right: none;
      border-bottom: 1px solid var(--line);
      padding: 12px;
      gap: 10px;
    }
    nav {
      flex-direction: row;
      flex-wrap: wrap;
    }
    .foot {
      display: none;
    }
    main {
      padding: 18px 14px;
    }
  }
</style>
