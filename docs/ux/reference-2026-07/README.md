# Portal revamp 2026-07 — visual reference

**Files in this directory are read-only visual reference for the AstraNull portal revamp.**

## What is here

| File | Purpose |
|---|---|
| `index.html` | Single-file SPA prototype (~3,260 lines). All screens, panels, modals, and interactions the revamp targets. |
| `styles.css` | Design tokens (Resend-derived void-black + frost-border palette) and all component CSS. |
| `app.js` | ENTITIES catalogs, routing (`navigate`), delegated click handlers, hydrators (`populateDetail`, `populateTargetDetail`, `populateFindingAffectedTargets`), and the demo data model. |

Origin: Open Design project `d0e85ac0-42c4-44a9-9698-b5784b2cd049` (2026-07-07). Files copied verbatim, `chmod 0444`.

## What this reference is (and isn't)

**Is:**

- The **visual target** for the React portal — colours, typography, layout, panel composition, and interaction affordances the revamp lands on.
- The **IA target** — sidebar structure, page count, per-page composition, tab structure, verdict/state taxonomy.
- The **interaction contract** — how the four verification chip states behave, how DNS TXT / LOA / provider-inventory flows sequence, how the SOC-gated queue lives inline on Test runs.

**Is not:**

- The final implementation. It is a demo SPA with a static `ENTITIES` catalog. The React port must wire every panel to the real API (see [`../14-portal-revamp-2026-07.md`](../14-portal-revamp-2026-07.md) for the per-panel API map).
- Complete on CRUD. The prototype demonstrates the read/verify/gating story but omits create/delete/edit flows on multiple surfaces. The full CRUD backlog lives in [`../15-crud-operations-backlog.md`](../15-crud-operations-backlog.md).
- Authoritative for RBAC. The prototype uses a demo role picker. Every RBAC decision must come from `src/contracts/roles.mjs` + `apps/web/react/src/lib/route-access.ts`.

## How to open

The prototype is a single self-contained HTML file — open `index.html` in any modern browser. There is no build step. `app.js` is loaded as a plain script; `styles.css` provides the tokens.

## Read order for implementers

1. **[`../14-portal-revamp-2026-07.md`](../14-portal-revamp-2026-07.md)** — the migration spec. Names each prototype screen, its React target file, the panels/components to build, and the exact interaction contract.
2. **[`../15-crud-operations-backlog.md`](../15-crud-operations-backlog.md)** — every CRUD/delete/edit gap the prototype leaves open.
3. `index.html` in this directory — the visual reference. Open once you have the spec in hand so you can see what each named panel looks like.
4. `styles.css` — for the design tokens and component classes to port into `apps/web/react/src/styles.css`.
5. `app.js` — for the demo data shape and the delegated action names. Do **not** port `ENTITIES`; the React app has its own API layer (`apps/web/react/src/lib/api.ts`).

## Anti-drift rule

If the prototype and this documentation ever disagree, the documentation wins. The prototype is a **snapshot** taken on 2026-07-07 and will not be updated as the React port evolves. Do not port bugs from the prototype (e.g. the demo data catalog is intentionally sparse for some entities — that's a fixture limit, not a design decision).
