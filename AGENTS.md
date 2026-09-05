# AGENTS.md

Guidance for AI coding agents and contributors working in this repository.
Read this before making changes.

## What this project is

`router-monitor` is a lightweight network observability tool and daemon for Linux routers and gateways. It collects eBPF traffic counters at TC ingress/egress, ARP-based device discovery, and TCP internet reachability checks. It exposes Prometheus metrics, runs a Connect-RPC service with an embedded SQLite time-series database, and embeds a web dashboard SPA.

## Essential Commands

### Go Backend
```bash
go test ./...                       # run all unit tests
GOARCH=amd64 go test ./...          # run tests targeting amd64 (eBPF stubs/collectors)
go build ./...                      # build all packages
task go-build                       # build Linux amd64 binary
```

### Protobuf & Code Generation
```bash
task buf-generate                   # generate protobuf and Connect-RPC definitions
task go-generate                    # regenerate eBPF artifacts via Docker
```

### Web UI (Frontend)
The web application is located in `web/` (React 19 + Vite 8 + TypeScript + Tailwind CSS v4). It is embedded into the Go binary at `internal/web/dist/`.

```bash
cd web && bun install               # install frontend dependencies (or task web-install)
cd web && bun run dev               # start Vite dev server on :9157 (or task web-dev)
cd web && bun run build             # typecheck & build frontend
task web-build                      # builds web frontend and syncs to internal/web/dist/
```

## Frontend & shadcn/ui Guidelines

- **Always use shadcn CLI tooling**: All UI component primitives in `web/src/components/ui/` **must** be generated using the official shadcn tooling (`bunx --bun shadcn@latest add <component>`). **Never manually write or hand-craft shadcn component primitives.**
- **Preset `bJMVaeaO`**: The project uses shadcn preset `bJMVaeaO` (`radix-nova` style, `stone` base palette, Tailwind CSS v4 with OKLCH variables). To apply or re-apply this preset, run:
  ```bash
  cd web && bunx --bun shadcn@latest apply --preset bJMVaeaO -y
  ```
- **Adding components**: To add a new UI primitive, navigate to `web/` and run:
  ```bash
  bunx --bun shadcn@latest add <component-name>
  ```
  Or with `--overwrite` if updating existing ones:
  ```bash
  bunx --bun shadcn@latest add <component-name> --overwrite
  ```
- **Configuration**: Configuration lives in `web/components.json`. It specifies the Vite template, Tailwind CSS v4 configuration, path aliases (`@/components/ui`, `@/lib/utils`), and Lucide icons.
- **Custom Utilities vs shadcn `utils.ts`**: shadcn CLI overwrites `web/src/lib/utils.ts` during initialization and preset application (keeping only `export { cn } from "cn"`). Therefore, domain utilities and formatters must live in `web/src/lib/format.ts` (or other files), not in `utils.ts`.
- **Custom Styling**: Do not modify generated component primitives in `web/src/components/ui/` with custom non-standard variants unless strictly necessary. Instead, use standard variants and compose styling via `className` and `cn(...)` in application components.
- **Package Manager**: Use `bun` for frontend package management and script execution in `web/`.

## Repo Structure

```
cmd/router-monitor/           # CLI entrypoint
internal/
  api/                        # Connect-RPC service implementation
  routermonitor/              # eBPF collector (C and Go), ARP discovery, internet reachability
  tsdb/                       # Embedded SQLite time-series database & background sampler
  web/                        # Embedded web SPA assets (dist/) and HTTP handler
proto/                        # Protobuf definitions
web/                          # React SPA frontend (Vite, Tailwind, shadcn/ui, Connect-RPC)
  src/
    components/ui/            # shadcn/ui components (generated via shadcn CLI)
    components/               # Domain-specific UI tabs and header
    lib/                      # Connect-RPC client and utilities
dashboard/                    # Grafana dashboard source & generated JSON
Taskfile.yaml                 # Task runner commands
```

## Conventions

- Run tests (`go test ./...`) and web build (`cd web && bun run build`) before committing.
- Follow conventional commits: `feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `test:`.
- Check `git status` after changes and maintain a clean commit history.
