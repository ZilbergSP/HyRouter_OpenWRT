# HyRouter development notes

HyRouter is HyRoute for OpenWrt routers: a Go daemon (hyrouterd) with an
embedded Svelte 5 web UI that routes the whole LAN through Hysteria 2 and
VLESS servers by rules on devices, sites, IPs, ports and geosite/geoip
lists. Interception: nftables (own table `inet hyrouter`) with TPROXY.
Architecture and plan: docs/ARCHITECTURE.md. The users speak Russian:
answer in Russian, UI text and docs are Russian.

The repository is private. HyRoute (github.com/lardan099/hyroute, public,
MIT) is the source of the copied packages; it is checked out next to this
one at ../HyRoute. This repository lives in D:\Work\Projects\HyRoute_OpenWRT.

## Workflow

- Development happens on `main`: `git pull --rebase origin main` before
  changing code; push each finished and checked piece with
  `git push origin HEAD:main`. Never force-push main.
- Open work is tracked in GitHub issues of this repository.

## Code copied from HyRoute

- docs/hyroute-sync.md lists every copied package, the HyRoute commit it
  matches and how it differs. When a fix lands in HyRoute, port it
  (`diff -r ../HyRoute/internal/<pkg> internal/<pkg>`) and update the row.
- HyRoute's MIT notice stays in THIRD-PARTY-NOTICES.txt.
- Module path: `github.com/zilbergsp/hyrouter` (lower case).

## Commits

- English messages: a subject line and a short body of what and why.
- No session-link trailers. `Co-Authored-By` is fine.

## Checks before a push

- `gofmt -l .` prints nothing; `go vet ./...`; `go test ./...` (Linux).
- UI changes: `cd web && npx svelte-check --threshold warning && npx vite build`;
  web/dist is committed with the change.
- The maintainer's PC is Windows without Go, by choice: every Go check
  (gofmt, tidy, vet, tests, cross-builds) runs in GitHub CI only
  (.github/workflows/ci.yml). Push, then follow the run (`gh run watch`,
  `gh run view --log-failed`) and fix from its output. Format Go code by
  hand as gofmt does (tabs, aligned comments in struct fields). Never run
  WSL, Docker, network or nftables tests on that PC: it drops their
  internet.
- Both editions: CI vets and tests with `-tags lite` too and builds Lite
  for mipsle and armv7; test/netns.sh (routing) and the packages job
  (install in the OpenWrt 24.10 and 25.12 images) run in CI only.
- Build web/dist from LF copies of the sources, as CI on Linux does, or
  the dist check fails.

## Releases

- Tag (annotated, "HyRouter X.Y.Z") only a commit of main whose CI is
  green, with docs/release-notes/vX.Y.Z.md in place; release.yml checks
  both. Versions before 1.0 are betas (pre-releases). A published tag is
  never moved or reused: a fix goes into the next version.
- Until it has been tried on real routers, the notes say what CI checked
  and that it was not checked on hardware.

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
