<script lang="ts">
  import { api, errorText } from '../lib/api';
  import type { StateView, ZapretView } from '../lib/types';

  let {
    z,
    onsaved,
  }: { z: ZapretView; onsaved: (r: { state: StateView; zapret: ZapretView }) => void } = $props();

  const tg = $derived(z.telegram);
  const routes = $derived(tg.stats.routes ?? {});

  let busy = $state(false);
  let error = $state('');
  // The Workers field starts from the saved ones and is the user's after.
  function savedWorkers() {
    return z.telegram.workers.join('\n');
  }
  let workers = $state(savedWorkers());

  async function save(enabled: boolean, cloudflare: boolean) {
    busy = true;
    error = '';
    try {
      const list = workers
        .split('\n')
        .map((s) => s.trim())
        .filter(Boolean);
      onsaved(await api.saveTelegram({ enabled, cloudflare, workers: list }));
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  const clock = (s: string) => new Date(s).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
</script>

<div class="card">
  <h2>Telegram без VPN</h2>
  <p class="muted small">
    Telegram на всех устройствах сети ходит к своим серверам через WebSocket веб-версии Telegram — эти адреса блокируют
    редко. На телефонах и компьютерах ничего настраивать не нужно: HyRouter перехватывает соединения Telegram сам. Если
    WebSocket не отвечает, Telegram идёт через Cloudflare, основной сервер VPN или напрямую. Звонки так не идут.
  </p>
  <label class="check field">
    <input type="checkbox" checked={tg.enabled} disabled={busy} onchange={(e) => save(e.currentTarget.checked, tg.cloudflare)} />
    <strong>Включить</strong>
  </label>
  <label class="check field">
    <input type="checkbox" checked={tg.cloudflare} disabled={busy} onchange={(e) => save(tg.enabled, e.currentTarget.checked)} />
    Запасной путь через Cloudflare
  </label>
  <p class="muted small">
    Домены на Cloudflare держит автор tg-ws-proxy, список обновляется раз в час. Переписку Cloudflare не видит (её шифрует
    Telegram), но видит, что в сети пользуются Telegram.
  </p>

  {#if tg.enabled && !tg.running}
    <div class="notice">Включится, когда HyRouter маршрутизирует сеть.</div>
  {/if}
  {#if tg.running && tg.health}
    {@const h = tg.health}
    {#if h.ws}
      <p class="small ok-t">
        ✓ Telegram отвечает через WebSocket{h.wsRoute === 'ws-fronted' ? ' (под другим именем: прямое заблокировано)' : ''},
        {h.wsMillis} мс · проверено в {clock(h.at)}
      </p>
    {:else if h.fallback || h.cf}
      {@const viaCF = h.cf && (tg.cloudflareFirst || !h.fallback)}
      <div class="notice">
        WebSocket сейчас не отвечает — Telegram идёт
        {viaCF ? 'через Cloudflare' : h.fallback === 'vpn' ? 'через основной сервер VPN' : 'напрямую к серверам Telegram'}.
        HyRouter проверяет снова каждые 5 минут и вернётся к WebSocket, когда он заработает.
        {#if h.wsError}<span class="muted">({h.wsError})</span>{/if}
      </div>
    {:else}
      <div class="notice bad">
        Telegram не отвечает ни через WebSocket, ни {tg.cloudflare ? 'через Cloudflare, ни ' : ''}через VPN, ни напрямую. Проверьте
        интернет и основной сервер.
        <span class="muted">({h.wsError ?? ''}{h.fallbackError ? '; ' + h.fallbackError : ''})</span>
      </div>
    {/if}
    {#if tg.cloudflare || tg.workers.length > 0}
      <p class="small {h.cf ? 'ok-t' : 'muted'}">
        {#if h.cf}
          ✓ Запасной путь через {h.cfRoute === 'worker' ? 'ваш Worker' : 'Cloudflare'} отвечает, {h.cfMillis} мс{tg.cloudflareFirst
            ? ' — обход DPI его пропускает, он идёт раньше VPN'
            : ''}.
        {:else}
          Запасной путь через Cloudflare сейчас не отвечает{tg.cloudflareFirst
            ? ''
            : ' (возможно, провайдер режет Cloudflare: поможет обход DPI для Discord или своих сайтов)'}.
        {/if}
      </p>
    {/if}
  {/if}
  {#if tg.running && tg.stats.total > 0}
    <p class="small">
      Соединений сейчас: {tg.stats.active}. Всего: через WebSocket {(routes['ws'] ?? 0) + (routes['ws-fronted'] ?? 0)}{tg.cloudflare ||
      tg.workers.length
        ? `, через Cloudflare ${(routes['cloudflare'] ?? 0) + (routes['worker'] ?? 0)}`
        : ''}, через VPN {routes['vpn'] ?? 0}, напрямую {routes['tcp'] ?? 0}{tg.stats.failed
        ? `, не открылось ${tg.stats.failed}`
        : ''}.
    </p>
    {#if tg.stats.mediaOff?.length}
      <p class="muted small">
        Фото и видео с {tg.stats.mediaOff.map((d) => 'DC' + d).join(', ')} не приходили через WebSocket — час они идут другим
        путём (так бывает на аккаунтах без Premium).
      </p>
    {/if}
    {#if tg.stats.lastError}<p class="muted small">Последняя ошибка: {tg.stats.lastError}</p>{/if}
  {/if}

  <details>
    <summary class="small">Свои Cloudflare Workers</summary>
    <p class="muted small">
      Свой бесплатный посредник вместо чужих доменов: Worker на Cloudflare, который открывает соединение к серверу Telegram
      (как в tg-ws-proxy). По одному адресу в строке, вида <code>имя.аккаунт.workers.dev</code>, не больше пяти.
    </p>
    <textarea rows="3" bind:value={workers} placeholder="tg.myname.workers.dev"></textarea>
    <button disabled={busy} onclick={() => save(tg.enabled, tg.cloudflare)}>Сохранить Workers</button>
  </details>
  {#if error}<div class="notice bad">{error}</div>{/if}
</div>

<style>
  .ok-t {
    color: var(--ok);
  }
  details {
    margin-top: 10px;
  }
  details textarea {
    margin: 6px 0;
  }
</style>
