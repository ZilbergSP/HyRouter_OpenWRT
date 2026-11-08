# Код из HyRoute

Пакеты `internal/` ниже скопированы из HyRoute (`github.com/lardan099/hyroute`,
MIT) с коммита `d68dcbe` (v1.3.20). При копировании изменены только пути
импорта (`github.com/lardan099/hyroute` → `github.com/zilbergsp/hyrouter`) и
убраны файлы для Windows и macOS (`*_windows*.go`, `*_darwin*.go`).

Исправление в HyRoute переносится так: `diff -r ../HyRoute/internal/<пакет>
internal/<пакет>`, перенести нужное, поправить в таблице коммит и состояние.

| Пакет | С коммита | Состояние |
|---|---|---|
| `dnscache` | d68dcbe | как есть |
| `dnspolicy` | d68dcbe | как есть; программа станет устройством (этап 2) |
| `dnsproxy` | d68dcbe | как есть |
| `flows` | d68dcbe | как есть |
| `geodata` | d68dcbe | как есть |
| `groups` | d68dcbe | как есть |
| `hy2uri` | d68dcbe | как есть |
| `hysteria` | 9c5c7b3 | как есть (с `child.go` из v1.3.21 для `nfqws2`); запуск процессов на Linux — этап 2 |
| `logx` | d68dcbe | как есть |
| `procinfo` | d68dcbe | только `procinfo.go`: тип `Info` для условия «программы» в `rules` (на роутере не используется) |
| `release` | d68dcbe | как есть |
| `ruleconv` | d68dcbe | как есть |
| `rules` | d68dcbe | + условие «устройства» (`device.go`; поле `Devices`, `Subject.MAC`/`Src`, `Query.Device`); программы остаются, на роутере не используются |
| `sniff` | d68dcbe | как есть |
| `socks5` | d68dcbe | как есть |
| `stats` | d68dcbe | как есть; разрез «программа» станет «устройством» |
| `subfmt` | d68dcbe | как есть |
| `tunnels` | d68dcbe | как есть |
| `vless` | d68dcbe | как есть |
| `zapret` | 9c5c7b3 | `nfqws2` вместо `winws2`: `--qnum`/`--fwmark`/`--user` вместо фильтров WinDivert (`build.go`), правила nftables (`nft.go`, новый), без `ProbeExclude`/`ProbeOnly`; методы, списки, план, подбор, проверки и супервизор — как есть |

Ещё не перенесены, будут переделаны под роутер: `relay` (TPROXY вместо
reflect-NAT), `store`, `settings`, контроллер `app`.
