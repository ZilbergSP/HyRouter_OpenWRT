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
| `hysteria` | d68dcbe | как есть; запуск процессов на Linux — этап 2 |
| `logx` | d68dcbe | как есть |
| `procinfo` | d68dcbe | только `procinfo.go`; временно, пока правила не перешли на устройства |
| `release` | d68dcbe | как есть |
| `ruleconv` | d68dcbe | как есть |
| `rules` | d68dcbe | как есть; программы станут устройствами (этап 2) |
| `sniff` | d68dcbe | как есть |
| `socks5` | d68dcbe | как есть |
| `stats` | d68dcbe | как есть; разрез «программа» станет «устройством» |
| `subfmt` | d68dcbe | как есть |
| `tunnels` | d68dcbe | как есть |
| `vless` | d68dcbe | как есть |

Ещё не перенесены, будут переделаны под роутер: `relay` (TPROXY вместо
reflect-NAT), `store`, `settings`, контроллер `app`.
