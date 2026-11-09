# Код из HyRoute

Пакеты `internal/` ниже скопированы из HyRoute (`github.com/lardan099/hyroute`,
MIT) и сверены с коммитом `01032d2` (v1.3.25). При копировании изменены только пути
импорта (`github.com/lardan099/hyroute` → `github.com/zilbergsp/hyrouter`) и
убраны файлы для Windows и macOS (`*_windows*.go`, `*_darwin*.go`).

Исправление в HyRoute переносится так: `diff -r ../HyRoute/internal/<пакет>
internal/<пакет>`, перенести нужное, поправить в таблице коммит и состояние.

| Пакет | С коммита | Состояние |
|---|---|---|
| `dnscache` | 01032d2 | как есть |
| `dnspolicy` | 01032d2 | + устройство в `Requester` (`MAC`, `Src`): правила для устройств решают и их DNS-запросы |
| `dnsproxy` | 01032d2 | как есть |
| `flows` | 01032d2 | как есть |
| `geodata` | 01032d2 | + `export.go` (только HyRouter): категория в строки и обратно, сети geoip (`IPSet.Prefixes`), опубликованная контрольная сумма (`Updater.PublishedSum`) |
| `groups` | 01032d2 | как есть |
| `hy2uri` | 01032d2 | как есть |
| `hysteria` | 01032d2 | как есть (с `child.go` из v1.3.21 для `nfqws2`); на Linux ядро получает `Pdeathsig` и не переживает hyrouterd (`attrs_linux.go`, вызов в `process_other.go`) |
| `logx` | 01032d2 | как есть |
| `procinfo` | 01032d2 | только `procinfo.go`: тип `Info` для условия «программы» в `rules` (на роутере не используется) |
| `release` | 01032d2 | как есть |
| `ruleconv` | 01032d2 | как есть |
| `rules` | 01032d2 | + условие «устройства» (`device.go`; поле `Devices`, `Subject.MAC`/`Src`, `Query.Device`); план правил для компилятора nftables (`plan.go`: `Set.Plan`, `Set.NameRules`); «Навести порядок» (`tidy.go`) объединяет только правила для одних и тех же устройств, а правило для всех устройств между ними, задевающее те же сайты, объединение запрещает; программы остаются, на роутере не используются |
| `sniff` | 01032d2 | как есть |
| `socks5` | 01032d2 | + `Server.UDP` и `UDPSession` (только HyRouter): UDP-ассоциации через сессии встроенного клиента Hysteria (`internal/hycore`) |
| `stats` | 01032d2 | как есть; в разрезе «программа» — устройство (`Record.Process`/`Path` из `ctl/conns.go`) |
| `subfmt` | 01032d2 | как есть |
| `tunnels` | 01032d2 | как есть |
| `vless` | 01032d2 | как есть |
| `subs` | 01032d2 | из `internal/app` HyRoute: `links.go`, `merge.go`, `subinfo.go` (без предупреждений и ссылки поддержки контроллера) и загрузка, разбор и маски из `subs.go` (`fetch.go`, без снимков для отката) |
| `zapret` | 01032d2 | `nfqws2` вместо `winws2`: `--qnum`/`--fwmark`/`--user` вместо фильтров WinDivert (`build.go`), правила nftables (`nft.go`, новый; SYN-ACK всегда в очередь — для `ip_autottl`), без `ProbeExclude`/`ProbeOnly` и без быстрого перезапуска при 0xC0000142 (`DLLInitFailed`, только Windows); методы, генератор, фейки, списки, план, подбор, проверки и супервизор — как есть; `NFTConfig.Skip`: адреса серверов сразу в наборах исключений |

Переделаны под роутер, а не скопированы: `relay` (TPROXY вместо
reflect-NAT), `store`, контроллер `ctl`. Из контроллера `app` HyRoute
перенесены с переделкой: выбор сервера с группами (`engine/groups.go` →
`ctl/groups.go`), сканер больших групп (`groupscan.go`), подписки
(`subs.go` → `ctl/subs.go`), обход DPI с подбором и самопроверкой
(`zapret.go`, `zapretheal.go` → `ctl/zapret.go`), план и откат
восстановления (идея `backup*.go` → `ctl/backup.go`). Исправления этих
файлов HyRoute переносятся вручную.
