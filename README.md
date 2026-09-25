# payload-access-control

Role-based access control for [Payload CMS 3](https://payloadcms.com).

One plugin adds everything a multi-editor Payload project needs:

- a **Roles** collection with a per-collection permission matrix — read / create / update / delete checkboxes per collection and global, grouped in rows
- `roles` relation + `isAdmin` superuser checkbox **injected into your auth collection**
- automatic gating of collections without explicit access rules (`autoAccess`)
- ready-made access helpers you can use directly, or write your own on top of exported `hasPermission`

## Install

```bash
pnpm add payload-access-control
```

Requires Payload 3. Peer deps: `payload`, `@payloadcms/ui`, `react`.

## Quick start

```ts
import { buildConfig } from 'payload'
import { roleAccessPlugin } from 'payload-access-control'

export default buildConfig({
  admin: { user: 'admins' },
  collections: [Admins, Users, Posts, Media],
  globals: [SiteSettings],
  plugins: [roleAccessPlugin()],
})
```

Zero options needed. Out of the box:

| | |
|---|---|
| Roles collection | created as `roles`, grouped under **Access Control** in the admin sidebar |
| Role fields | `roles` + `isAdmin` injected into `admins` (your `admin.user` collection) |
| Governed | every collection and global except auth collections and Roles itself |
| Access | any collection/global without its own access rule gets `adminOrRole` on every op — bare collections are **never left at Payload's public-read default** |
| Existing rules | anything you already defined stays exactly as-is, untouched |
| Admin panel | users with no roles and no `isAdmin` never reach the panel — an `access.admin` gate (`isAdmin` or ≥1 role) is injected into the user collection unless you define your own |

Create your first superuser (see [Bootstrap](#bootstrapping-the-first-superuser)), then define roles in the admin UI.

## The permission matrix

Each role holds permission rows. A row picks target collections — specific slugs and/or **All collections & globals** (`*`) — plus which ops it grants on them:

- `*` covers every governed collection/global, **including ones added after the role was saved**
- multiple roles per user; grants **union** across roles
- checkboxes for ops already open to everyone (via `publicAccess`) render disabled — granting them would do nothing
- checking create/update/delete auto-checks `read` (a note appears; uncheck freely) — the admin sidebar only shows a collection its `read` grants, so write-without-read is API-only
- rows are additive; combine freely, e.g. one row `*` + read, another `posts` + update/delete
- roles only **grant** — they never revoke or narrow. Ops you open yourself (`publicAccess`, custom rules) stay open to everyone regardless of grants, and a collection stays visible to anyone its own access config already lets in. A role user seeing a "public" collection is config, not a grant leak.

## Options

| Option | Default | |
|---|---|---|
| `userCollection` | `admin.user`, else first auth collection | the single auth collection that gets `roles` + `isAdmin` injected (skipped if the fields already exist) |
| `collections` | `'*'` | governed collections — `'*'` = all except auth collections and Roles, or an explicit slug list |
| `globals` | `'*'` | governed globals, independent of `collections` — `'*'` = all, or an explicit slug list |
| `rolesSlug` | `'roles'` | slug (and table name) of the Roles collection |
| `group` | `'Access Control'` | admin sidebar group for the Roles collection — any label, or `''` to leave ungrouped |
| `exclude` | `undefined` | slugs kept out of the default `'*'` sets — `{ collections?: string[], globals?: string[] }` |
| `autoAccess` | `true` | fill undefined access ops on governed collections/globals with `adminOrRole` — ungranted users see nothing (Payload hides nav/routes on `false` read). Pass `false` to keep Payload's defaults and gate everything by hand |

```ts
roleAccessPlugin({
  userCollection: 'admins',
  collections: '*',
  exclude: { collections: ['internal-logs'] },
  autoAccess: false, // gate manually with the helpers instead
})
```

`userCollection` **must be an auth collection** — the plugin throws at boot otherwise (typo guard). Only one collection can be roleable: role grants are global and don't distinguish which auth collection a user logs in from, so a second roleable collection would cross-leak grants.

## Access helpers

| Helper | Grants |
|---|---|
| `publicAccess` | everyone — ops marked with it render disabled in the matrix |
| `adminOnly` / `adminOnlyField` | superusers (`isAdmin`) only |
| `adminOrRole(slug, op)` / `adminOrRoleField` | superusers or a role granting that op |
| `selfOrAdmin(slug)` | superusers, or the user's own doc — for auth collections role users must never reach |
| `selfOrGranted(slug, op)` | superusers, a role granting that op, or the user's own doc (same collection) — read/update/delete |
| `publicOrGrantedOps(slug, 'read')` | granted users; everyone else only sees docs whose `access` field equals `public` |
| `hasPermission(req, slug, op)` | the raw check the helpers use |
| `accessField` | the `public`/`private` select pairing with `publicOrGrantedOps` |

```ts
import { adminOnly, adminOrRole, publicAccess, publicOrGrantedOps, accessField } from 'payload-access-control'

export const Posts: CollectionConfig = {
  slug: 'posts',
  access: {
    read: publicOrGrantedOps('posts', 'read'),
    create: adminOrRole('posts', 'create'),
    update: adminOrRole('posts', 'update'),
    delete: adminOnly,
  },
  fields: [accessField /* ... */],
}
```

For public reads without the public/private split, set `read: publicAccess` — the read checkbox then renders disabled for that collection in the matrix.

## Security model

- **Auth collections and Roles itself are never governable** — a role granting permissions on the users collection would allow self-grant escalation. The Roles collection is readable/writable by superusers only, so role users can never discover or edit grants.
- **Roleless users cannot enter the admin panel.** The plugin injects `access.admin` (superuser or ≥1 role) into the user collection; Payload enforces it on every admin route. A roleless user can still authenticate against REST/GraphQL — every governed op stays `false` — they just never get a panel. Define your own `access.admin` to override.
- `isAdmin` = superuser: bypasses every check, including the matrix. Its create/update field access is superuser-only, so role users can't flip it.
- Anonymous requests get nothing (except ops you explicitly open with `publicAccess` / `publicOrGrantedOps`).
- Adding collections or globals later needs **no migration and no role edits** — the matrix derives from your config on every boot, and `*` grants cover newcomers automatically.

## Bootstrapping the first superuser

The injected `isAdmin` checkbox is superuser-writable only — with no superuser yet, nobody can grant it from the UI. Bootstrap the first one with a hook (promotes only while the collection is empty):

```ts
const promoteOnBootstrap: CollectionBeforeChangeHook = ({ data, req, operation }) => {
  if (!req.user && operation === 'create') data.isAdmin = true
  return data
}

// in your auth collection:
access: {
  create: async ({ req }) => {
    if (req.user) return req.user.isAdmin === true
    const { totalDocs } = await req.payload.count({ collection: 'admins' })
    return totalDocs === 0 // unauthenticated create only while empty
  },
},
hooks: { beforeChange: [promoteOnBootstrap] },
```

Alternative: flip `isAdmin` directly in the database for one user.

## Non-goals

Your auth collection's own access rules (first-user bootstrap style, self-edit, public signup) stay yours — the plugin only injects fields and the Roles collection. Field-level permissions beyond `isAdmin`/`roles` protection are not part of the matrix.

## License

MIT
