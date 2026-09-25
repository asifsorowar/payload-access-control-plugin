import type { CheckboxField, CollectionConfig, GlobalConfig, PayloadRequest, Plugin } from 'payload'

import type { PermedUser, PermissionOp } from './access.js'
import { adminOnly, adminOnlyField, adminOrRole, publicAccess } from './access.js'

export type RoleAccessConfig = {
  /**
   * Governed collections in the Roles permission matrix.
   * '*' (default): every collection except auth collections and Roles. Explicit list: only those slugs.
   * Auth collections and Roles are never governable (self-grant escalation).
   */
  collections?: '*' | string[]
  /** Governed globals — independent of `collections`. '*' (default): every global. Explicit list: only those. */
  globals?: '*' | string[]
  /**
   * The auth collection that carries roles — `roles` relation and `isAdmin` checkbox are injected
   * (skipped when the field already exists). Default: `admin.user`, else the first auth collection.
   * Only one collection can be roleable — role grants don't distinguish which auth collection the
   * bearer logs in from, so a second roleable collection would cross-leak grants.
   */
  userCollection?: string
  /** Slug of the Roles collection. Default: 'roles'. */
  rolesSlug?: string
  /** Admin UI sidebar group for the Roles collection. Default: 'Access Control'. Pass '' to leave ungrouped. */
  group?: string
  /**
   * Fill undefined access ops on governed collections/globals with adminOrRole — ungranted users
   * get false and Payload hides the collection from nav and routes. Defined ops stay untouched.
   * Default: true; pass false to opt out and keep Payload's open defaults.
   */
  autoAccess?: boolean
  /** Slugs kept out of the default `'*'` sets, per collections/globals. */
  exclude?: {
    collections?: string[]
    globals?: string[]
  }
}

const OPS: PermissionOp[] = ['read', 'create', 'update', 'delete']

/** slug → ops already open to everyone (access fn is the exported `publicAccess`); those checkboxes render disabled. */
function openForAllAccess(
  configs: (CollectionConfig | GlobalConfig)[],
): Record<string, PermissionOp[]> {
  const out: Record<string, PermissionOp[]> = {}
  for (const c of configs) {
    const ops = OPS.filter((op) => (c.access as Record<string, unknown> | undefined)?.[op] === publicAccess)
    if (ops.length) out[c.slug] = ops
  }
  return out
}

/** Fill undefined access ops with adminOrRole — defined ops untouched. */
function withAutoAccess(
  c: CollectionConfig | GlobalConfig,
  rolesSlug: string,
): CollectionConfig | GlobalConfig {
  const ops: PermissionOp[] = 'auth' in c ? OPS : ['read', 'update']
  const access = { ...(c.access as Record<string, unknown>) }
  let changed = false
  for (const op of ops) {
    if (access[op] === undefined) {
      access[op] = adminOrRole(c.slug, op, rolesSlug)
      changed = true
    }
  }
  return changed ? ({ ...c, access } as CollectionConfig | GlobalConfig) : c
}

function permissionCheckbox(name: PermissionOp, openOps: Record<string, PermissionOp[]>): CheckboxField {
  return {
    name,
    type: 'checkbox',
    defaultValue: false,
    admin: {
      width: '50%',
      components: {
        Field: {
          path: 'payload-access-control/client',
          exportName: 'PermissionCheckbox',
          clientProps: { openOps },
        },
      },
    },
  }
}

/** Admin-panel gate on the roleable collection: superuser or at least one role. Roleless users never reach the panel. */
const canAccessAdmin = ({ req }: { req: PayloadRequest }): boolean => {
  const user = req.user as PermedUser | null
  return !!user && (user.isAdmin === true || (Array.isArray(user.roles) && user.roles.length > 0))
}

function withRoleFields(collection: CollectionConfig, rolesSlug: string): CollectionConfig {
  const has = (name: string) => collection.fields.some((f) => 'name' in f && f.name === name)

  const extra: CollectionConfig['fields'] = []
  if (!has('isAdmin')) {
    extra.push({
      name: 'isAdmin',
      type: 'checkbox',
      defaultValue: false,
      label: 'Superuser (bypasses all permission checks)',
      access: { create: adminOnlyField, update: adminOnlyField },
    })
  }
  if (!has('roles')) {
    extra.push({
      name: 'roles',
      type: 'relationship',
      relationTo: rolesSlug,
      hasMany: true,
      access: { create: adminOnlyField, update: adminOnlyField },
      admin: {
        // Roles are pointless for a superuser
        condition: (_data, sibling, { user }) =>
          !!user && !(sibling as { isAdmin?: boolean })?.isAdmin,
      },
    })
  }
  let out = extra.length ? ({ ...collection, fields: [...collection.fields, ...extra] } as CollectionConfig) : collection
  if (out.access?.admin === undefined) {
    out = { ...out, access: { ...out.access, admin: canAccessAdmin } }
  }
  return out
}

function rolesCollection({
  governed,
  openOps,
  rolesSlug,
  group,
}: {
  governed: (CollectionConfig | GlobalConfig)[]
  openOps: Record<string, PermissionOp[]>
  rolesSlug: string
  group?: string
}): CollectionConfig {
  return {
    slug: rolesSlug,
    admin: {
      useAsTitle: 'name',
      ...(group !== '' ? { group } : {}),
    },
    access: {
      // superuser only — the permission matrix is never readable by role users
      read: adminOnly,
      // adminOnly: role grants on user collections must never reach Roles — self-grant escalation
      create: adminOnly,
      update: adminOnly,
      delete: adminOnly,
    },
    fields: [
      {
        name: 'name',
        type: 'text',
        required: true,
        label: 'Name',
        admin: { description: 'e.g. "Editors", "Marketing — read only"' },
      },
      {
        name: 'permissions',
        type: 'array',
        label: 'Collection permissions',
        labels: { singular: 'Permission', plural: 'Permissions' },
        fields: [
          {
            name: 'collections',
            type: 'select',
            hasMany: true,
            required: true,
            options: [
              { label: 'All collections & globals', value: '*' },
              ...governed.map((c) => c.slug),
            ],
            admin: {
              description:
                "Pick specific collections, or 'All collections & globals' to apply the checked permissions to everything — new ones added later are covered automatically.",
            },
          },
          {
            type: 'row',
            fields: OPS.map((op) => permissionCheckbox(op, openOps)),
          },
        ],
      },
    ],
  }
}

export const roleAccessPlugin = (options: RoleAccessConfig = {}): Plugin => (config) => {
  const rolesSlug = options.rolesSlug ?? 'roles'
  const allCollections = config.collections ?? []
  const allGlobals = config.globals ?? []
  const authSlugs = allCollections.filter((c) => c.auth).map((c) => c.slug)
  const userSlug = options.userCollection ?? config.admin?.user ?? authSlugs[0]
  if (userSlug && !authSlugs.includes(userSlug)) {
    throw new Error(`roleAccessPlugin: userCollection '${userSlug}' is not an auth collection`)
  }
  const excludedCols = new Set([...authSlugs, rolesSlug, ...(options.exclude?.collections ?? [])])
  const excludedGlobals = new Set([rolesSlug, ...(options.exclude?.globals ?? [])])
  const pick = (slug: string, requested: '*' | string[], excluded: Set<string>) =>
    !excluded.has(slug) && (requested === '*' || requested.includes(slug))

  const requestedCols = options.collections ?? '*'
  const requestedGlobals = options.globals ?? '*'

  const governed = [
    ...allCollections.filter((c) => pick(c.slug, requestedCols, excludedCols)),
    ...allGlobals.filter((g) => pick(g.slug, requestedGlobals, excludedGlobals)),
  ]

  const governedSlugs = new Set(governed.map((c) => c.slug))
  const auto = <T extends CollectionConfig | GlobalConfig>(c: T): T =>
    options.autoAccess !== false && governedSlugs.has(c.slug)
      ? (withAutoAccess(c, rolesSlug) as T)
      : c

  return {
    ...config,
    collections: [
      ...allCollections.map((c) => auto(c.slug === userSlug ? withRoleFields(c, rolesSlug) : c)),
      rolesCollection({
        governed,
        openOps: openForAllAccess(governed),
        rolesSlug,
        group: options.group ?? 'Access Control',
      }),
    ],
    globals: allGlobals.map(auto),
  }
}
