# HyRouter development notes

HyRouter is HyRoute for OpenWrt routers: a Go daemon (hyrouterd) with an
embedded Svelte 5 web UI that routes the whole LAN through Hysteria 2 and
VLESS servers by rules on devices, sites, IPs, ports and geosite/geoip
lists. Interception: nftables (own table `inet hyrouter`) with TPROXY.
Architecture and plan: docs/ARCHITECTURE.md. The users speak Russian:
answer in Russian, UI text and docs are Russian.

The repository is private. HyRoute (github.com/lardan099/hyroute, public,
MIT) is the source of the copied packages; it is checked out next to this
one at ../HyRoute.

## Workflow

- Development happens on `main`: `git pull --rebase origin main` before
  changing code; push each finished and checked piece with
  `git push origin HEAD:main`. Never force-push main.
- Open work is tracked in GitHub issues of this repository.

## Code copied from HyRoute

- A copied package keeps a line `// From HyRoute <commit>: <path>` in its
  doc comment. When a fix lands in HyRoute, port it and move the commit.
- HyRoute's MIT notice stays in THIRD-PARTY-NOTICES.txt.

## Commits

- English messages: a subject line and a short body of what and why.
- No session-link trailers. `Co-Authored-By` is fine.

## Checks before a push

- `gofmt -l .` prints nothing; `go vet ./...`; `go test ./...` (Linux).
- UI changes: `cd web && npx svelte-check --threshold warning && npx vite build`;
  web/dist is committed with the change.
- The maintainer's PC is Windows without Go (check `go version` first). Do
  not run WSL, Docker, network or nftables tests there: it drops their
  internet. Linux, netns and QEMU tests run in GitHub CI only; say in the
  report what was checked locally and what is left to CI.

## Never commit

- Share links (hysteria2://, hy2://, vless://), passwords, UUIDs, pins,
  SNI, server IPs, subscription URLs or hosts of the users. Test links live
  in `.dev/` (gitignored). Mask secrets in every log line.
- Details of an unfixed vulnerability.

## Product decisions

- VPN traffic never goes direct: a down server, empty group or a crashed
  hyrouterd rejects the connection (or uses a fallback server).
- Direct traffic stays in the kernel and never depends on hyrouterd.
- Statistics never record which sites were visited: only devices, servers
  and groups.
