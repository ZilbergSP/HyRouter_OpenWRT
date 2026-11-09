<script lang="ts">
  import { api, errorText } from '../lib/api';
  import type { Platform } from '../lib/types';

  let { version, platform, onlogin }: { version: string; platform: Platform; onlogin: () => void } = $props();

  let password = $state('');
  let busy = $state(false);
  let error = $state('');

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    error = '';
    try {
      await api.login(password);
      password = '';
      onlogin();
    } catch (err) {
      error = errorText(err);
    } finally {
      busy = false;
    }
  }
</script>

<div class="wrap">
  <form class="card" onsubmit={submit}>
    <div class="brand">
      <img src="/favicon.svg" alt="" width="40" height="40" />
      <div>
        <h1>HyRouter</h1>
        <div class="muted small">раздельная маршрутизация для всей сети</div>
      </div>
    </div>
    <label class="field">
      <span>{platform === 'keenetic' ? 'Пароль root Entware' : 'Пароль root роутера'}</span>
      <!-- svelte-ignore a11y_autofocus -->
      <input type="password" autocomplete="current-password" bind:value={password} autofocus required />
    </label>
    {#if error}<div class="notice bad">{error}</div>{/if}
    <button class="primary" type="submit" disabled={busy || !password}>{busy ? 'Проверяю…' : 'Войти'}</button>
    <div class="muted small ver">версия {version}</div>
  </form>
</div>

<style>
  .wrap {
    min-height: 100vh;
    display: grid;
    place-items: center;
    padding: 16px;
  }
  form {
    width: min(380px, 100%);
    padding: 26px;
  }
  .brand {
    display: flex;
    gap: 12px;
    align-items: center;
    margin-bottom: 22px;
  }
  button {
    width: 100%;
    padding: 10px;
  }
  .ver {
    margin-top: 14px;
    text-align: center;
  }
</style>
