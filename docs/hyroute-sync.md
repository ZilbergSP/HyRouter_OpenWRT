# Код из HyRoute

Пакеты `internal/` ниже скопированы из HyRoute (`github.com/lardan099/hyroute`,
MIT) и сверены с коммитом `499b2ca` (v1.3.23). При копировании изменены только пути
импорта (`github.com/lardan099/hyroute` → `github.com/zilbergsp/hyrouter`) и
убраны файлы для Windows и macOS (`*_windows*.go`, `*_darwin*.go`).

Исправление в HyRoute переносится так: `diff -r ../HyRoute/internal/<пакет>
internal/<пакет>`, перенести нужное, поправить в таблице коммит и состояние.

| Пакет | С коммита | Состояние |
|---|---|---|
| `dnscache` | 499b2ca | как есть |
| `dnspolicy` | 499b2ca | как есть; программа станет устройством (этап 2) |
| `dnsproxy` | 499b2ca | как есть |
| `flows` | 499b2ca | как есть |
| `geodata` | 499b2ca | как есть |
| `groups` | 499b2ca | как есть |
| `hy2uri` | 499b2ca | как есть |
| `hysteria` | 499b2ca | как есть (с `child.go` из v1.3.21 для `nfqws2`); запуск процессов на Linux — этап 2 |
| `logx` | 499b2ca | как есть |
| `procinfo` | 499b2ca | только `procinfo.go`: тип `Info` для условия «программы» в `rules` (на роутере не используется) |
| `release` | 499b2ca | как есть |
| `ruleconv` | 499b2ca | как есть |
| `rules` | 499b2ca | + условие «устройства» (`device.go`; поле `Devices`, `Subject.MAC`/`Src`, `Query.Device`); «Навести порядок» (`tidy.go`) объединяет только правила для одних и тех же устройств, а правило для всех устройств между ними, задевающее те же сайты, объединение запрещает; программы остаются, на роутере не используются |
| `sniff` | 499b2ca | как есть |
| `socks5` | 499b2ca | как есть |
| `stats` | 499b2ca | как есть; разрез «программа» станет «устройством» |
| `subfmt` | 499b2ca | как есть |
| `tunnels` | 499b2ca | как есть |
| `vless` | 499b2ca | как есть |
| `zapret` | 499b2ca | `nfqws2` вместо `winws2`: `--qnum`/`--fwmark`/`--user` вместо фильтров WinDivert (`build.go`), правила nftables (`nft.go`, новый; SYN-ACK всегда в очередь — для `ip_autottl`), без `ProbeExclude`/`ProbeOnly` и без быстрого перезапуска при 0xC0000142 (`DLLInitFailed`, только Windows); методы, генератор, фейки, списки, план, подбор, проверки и супервизор — как есть |

Ещё не перенесены, будут переделаны под роутер: `relay` (TPROXY вместо
reflect-NAT), `store`, `settings`, контроллер `app`.
