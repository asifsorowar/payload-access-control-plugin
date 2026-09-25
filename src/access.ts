import type { Access, FieldAccess, PayloadRequest, SelectField, Where } from 'payload'

export type PermissionOp = 'read' | 'create' | 'update' | 'delete'

export type PermedUser = {
  id?: number
  isAdmin?: boolean
  roles?: unknown[]
  collection?: string
}

/**
 * Check user's roles for a granted permission on a collection/global slug.
 * Superuser (`isAdmin`) bypasses everything.
 * ponytail: one roles query per access check, no per-request cache — memo on req if profiling demands.
 */
export async function hasPermission(
  req: PayloadRequest,
  slug: string,
  op: PermissionOp,
  rolesSlug = 'roles',
): Promise<boolean> {
  const user = req.user as PermedUser | null
  if (!user) return false
  if (user.isAdmin) return true

  const roleIds = (user.roles ?? []).map((r) =>
    typeof r === 'object' && r !== null && 'id' in r ? (r as { id: number }).id : r,
  )
  if (!roleIds.length) return false

  const { docs } = await req.payload.find({
    collection: rolesSlug,
    where: { id: { in: roleIds } },
    depth: 0,
    limit: 100,
  })

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return docs.some((role: any) =>
    (role.permissions ?? []).some(
      (p: { collections?: string[]; [k: string]: unknown }) =>
        // '*' grants the op on every collection and global, present and future
        (p.collections ?? []).some((c) => c === '*' || c === slug) && p[op] === true,
    ),
  )
}

export const publicAccess: Access = () => true

/** Superuser only. */
export const adminOnly: Access = ({ req }: Parameters<Access>[0]) =>
  !!req.user && (req.user as PermedUser).isAdmin === true

/** Superuser or a role granting this op. */
export function adminOrRole(slug: string, op: PermissionOp, rolesSlug = 'roles'): Access {
  return async ({ req }) =>
    !!req.user &&
    ((req.user as PermedUser).isAdmin === true || (await hasPermission(req, slug, op, rolesSlug)))
}

/** Granted op passes; ungranted fall back to docs marked `public` — for read. */
export function publicOrGrantedOps(slug: string, op: PermissionOp, rolesSlug = 'roles'): Access {
  return async ({ req }): Promise<boolean | Where> =>
    (await adminOrRole(slug, op, rolesSlug)({ req })) || ({ access: { equals: 'public' } } as Where)
}

/** Superuser, or the user's own doc (same collection only) — for auth collections role users must never reach. */
export function selfOrAdmin(slug: string): Access {
  return ({ req }) => {
    const user = req.user as PermedUser | null
    if (user?.isAdmin) return true
    return user && user.collection === slug ? ({ id: { equals: user.id } } as Where) : false
  }
}

/** Superuser, a role granting this op, or the user's own doc (same collection only) — read/update/delete. */
export function selfOrGranted(slug: string, op: PermissionOp, rolesSlug = 'roles'): Access {
  return async ({ req }) => {
    const user = req.user as PermedUser | null
    if (!user) return false
    if (user.isAdmin === true) return true
    if (await hasPermission(req, slug, op, rolesSlug)) return true
    return user.collection === slug ? ({ id: { equals: user.id } } as Where) : false
  }
}

/** Superuser only, for field-level access. */
export const adminOnlyField: FieldAccess = ({ req }) =>
  !!req.user && (req.user as PermedUser).isAdmin === true

/** adminOrRole for fields — same role check, FieldAccess args. */
export function adminOrRoleField(slug: string, op: PermissionOp, rolesSlug = 'roles'): FieldAccess {
  return async ({ req }) =>
    !!req.user &&
    ((req.user as PermedUser).isAdmin === true || (await hasPermission(req, slug, op, rolesSlug)))
}

/** Shared `access` select — `public` readable by anyone, `private` gated by read permission. Pair with publicOrGrantedOps. */
export const accessField: SelectField = {
  name: 'access',
  type: 'select',
  defaultValue: 'public',
  options: [
    { label: 'Public', value: 'public' },
    { label: 'Private', value: 'private' },
  ],
  admin: { position: 'sidebar' },
}
