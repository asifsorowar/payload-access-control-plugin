import assert from 'node:assert/strict'
import { test } from 'node:test'

import type { CollectionConfig, GlobalConfig } from 'payload'

import { roleAccessPlugin } from './plugin.js'
import { hasPermission, publicAccess } from './access.js'

const col = (
  slug: string,
  auth = false,
  access?: Record<string, unknown>,
): CollectionConfig =>
  ({ slug, auth, fields: [], access }) as unknown as CollectionConfig
const glob = (slug: string, access?: Record<string, unknown>): GlobalConfig =>
  ({ slug, fields: [], access }) as unknown as GlobalConfig

const base = {
  admin: { user: 'admins' },
  collections: [col('admins', true), col('users', true), col('media'), col('pages'), col('logs')],
  globals: [glob('site-settings')],
}

type Incoming = Parameters<ReturnType<typeof roleAccessPlugin>>[0]
type Resolved = Awaited<ReturnType<ReturnType<typeof roleAccessPlugin>>>

const run = (opts?: Parameters<typeof roleAccessPlugin>[0]): Promise<Resolved> =>
  Promise.resolve(roleAccessPlugin(opts)(base as Incoming))

const matrixOptions = async (opts?: Parameters<typeof roleAccessPlugin>[0]) => {
  const out = await run(opts)
  const roles = (out.collections ?? []).find((c) => c.slug === 'roles')!
  const permissions = roles.fields.find((f) => 'name' in f && f.name === 'permissions') as {
    fields: { name: string; options: (string | { label: string; value: string })[] }[]
  }
  return permissions.fields[0].options.filter(
    (o) => (typeof o === 'object' ? o.value : o) !== '*',
  )
}

test("default '*' governs everything except auth + roles", async () => {
  assert.deepEqual(await matrixOptions(), ['media', 'pages', 'logs', 'site-settings'])
})

test('explicit lists pick only those, auth still blocked', async () => {
  assert.deepEqual(
    await matrixOptions({ collections: ['media', 'users'], globals: ['site-settings'] }),
    ['media', 'site-settings'],
  )
})

test('globals list alone leaves default collections', async () => {
  assert.deepEqual(await matrixOptions({ globals: ['site-settings'] }), [
    'media',
    'pages',
    'logs',
    'site-settings',
  ])
})

test('exclude object trims the default sets', async () => {
  assert.deepEqual(await matrixOptions({ exclude: { collections: ['logs'] } }), [
    'media',
    'pages',
    'site-settings',
  ])
  assert.deepEqual(await matrixOptions({ exclude: { globals: ['site-settings'] } }), [
    'media',
    'pages',
    'logs',
  ])
})

const fieldNames = (out: Resolved, slug: string) => {
  const c = (out.collections ?? []).find((x) => x.slug === slug)!
  return c.fields.map((f) => ('name' in f ? f.name : 'row')).filter((n) => n !== 'row')
}

test('default injects into admin.user only, other auth collections untouched', async () => {
  const out = await run()
  assert.deepEqual(fieldNames(out, 'admins'), ['isAdmin', 'roles'])
  assert.deepEqual(fieldNames(out, 'users'), [])
  assert.ok(!fieldNames(out, 'media').includes('roles'))
})

test('explicit userCollection overrides admin.user', async () => {
  const out = await run({ userCollection: 'users' })
  assert.deepEqual(fieldNames(out, 'users'), ['isAdmin', 'roles'])
  assert.deepEqual(fieldNames(out, 'admins'), [])
})

test('userCollection must be an auth collection', async () => {
  await assert.rejects(
    async () => roleAccessPlugin({ userCollection: 'media' })(base as Incoming),
    /not an auth collection/,
  )
})

test('pre-existing isAdmin/roles fields are not duplicated', async () => {
  const withFields: CollectionConfig = {
    slug: 'admins',
    auth: true,
    fields: [
      { name: 'isAdmin', type: 'checkbox' },
      { name: 'roles', type: 'relationship', relationTo: 'roles' },
    ],
  } as unknown as CollectionConfig
  const out = await Promise.resolve(
    roleAccessPlugin({ userCollection: 'admins' })({
      ...base,
      collections: [
        withFields,
        col('users', true),
        col('media'),
        col('pages'),
        col('logs'),
      ],
    } as Incoming),
  )
  const admins = (out.collections ?? []).find((c) => c.slug === 'admins')!
  const names = admins.fields.map((f) => ('name' in f ? f.name : 'row')).filter((n) => n !== 'row')
  assert.deepEqual(names, ['isAdmin', 'roles'])
})

const openOpsOf = async (cfg: Incoming) => {
  const out = await Promise.resolve(roleAccessPlugin()(cfg))
  const roles = (out.collections ?? []).find((c) => c.slug === 'roles')!
  const permissions = roles.fields.find((f) => 'name' in f && f.name === 'permissions') as {
    fields: {
      name?: string
      type?: string
      fields?: {
        name?: string
        admin?: { components?: { Field?: { clientProps?: { openOps?: Record<string, string[]> } } } }
      }[]
    }[]
  }
  const checkbox = (op: string) =>
    permissions
      .fields!.find((f) => f.type === 'row')!
      .fields!.find((f) => f.name === op)!
  return checkbox('read').admin!.components!.Field!.clientProps!.openOps!
}

test('publicAccess ops land in openOps → checkboxes disabled', async () => {
  const cfg = {
    admin: { user: 'admins' },
    collections: [
      col('admins', true),
      // pubmedia read is publicAccess, create is not
      col('pubmedia', false, { read: publicAccess }),
      col('media'),
    ],
    globals: [glob('site-settings', { read: publicAccess })],
  }
  assert.deepEqual(await openOpsOf(cfg as Incoming), {
    pubmedia: ['read'],
    'site-settings': ['read'],
  })
})

test('hasPermission queries roles by user role ids, depth 0', async () => {
  const calls: unknown[] = []
  const req = {
    user: { collection: 'users', isAdmin: false, roles: [7, { id: 9 }] },
    payload: {
      find: async (args: unknown) => {
        calls.push(args)
        return { docs: [{ permissions: [{ collections: ['media'], read: true }] }] }
      },
    },
  }
  assert.equal(await hasPermission(req as never, 'media', 'read'), true)
  assert.equal(calls.length, 1)
  assert.deepEqual(calls[0], {
    collection: 'roles',
    where: { id: { in: [7, 9] } },
    depth: 0,
    limit: 100,
  })
})

test('roleless non-superusers cannot access the admin panel', async () => {
  const out = await run()
  const admins = (out.collections ?? []).find((c) => c.slug === 'admins')!
  const admin = (admins.access as Record<string, unknown>).admin as (
    a: { req: { user: unknown } },
  ) => boolean
  assert.equal(admin({ req: { user: { isAdmin: true, roles: [] } } }), true)
  assert.equal(admin({ req: { user: { isAdmin: false, roles: [1] } } }), true)
  assert.equal(admin({ req: { user: { isAdmin: false, roles: [] } } }), false)
  assert.equal(admin({ req: { user: { isAdmin: false } } }), false)
  assert.equal(admin({ req: { user: null } }), false)
})

test('predefined access.admin stays untouched', async () => {
  const custom = () => true
  const cfg = {
    ...base,
    collections: [col('admins', true, { admin: custom }), ...base.collections.slice(1)],
  }
  const out = await Promise.resolve(roleAccessPlugin()(cfg as Incoming))
  const admins = (out.collections ?? []).find((c) => c.slug === 'admins')!
  assert.equal((admins.access as Record<string, unknown>).admin, custom)
  // gate lands even when role fields already exist and injection was skipped
  const withFields = await run()
  assert.ok(
    (withFields.collections ?? []).find((c) => c.slug === 'media')!.access?.admin === undefined,
  )
})

test('group option renames sidebar group, empty string ungroups', async () => {
  const groupOf = async (group?: string) => {
    const out = await run(group === undefined ? undefined : { group })
    const roles = (out.collections ?? []).find((c) => c.slug === 'roles')!
    return (roles.admin as { group?: string }).group
  }
  assert.equal(await groupOf(), 'Access Control')
  assert.equal(await groupOf('Permissions'), 'Permissions')
  assert.equal(await groupOf(''), undefined)
})

test('roles collection readable by superusers only', async () => {
  const out = await run()
  const roles = (out.collections ?? []).find((c) => c.slug === 'roles')!
  const read = (roles.access as { read: (args: { req: { user: unknown } }) => unknown }).read
  assert.equal(await read({ req: { user: { collection: 'admins', isAdmin: true } } }), true)
  assert.equal(
    await read({ req: { user: { collection: 'admins', isAdmin: false, roles: [1] } } }),
    false,
  )
  assert.equal(await read({ req: { user: null } }), false)
})

test('wildcard grant covers any collection, any slug', async () => {
  const req = {
    user: { collection: 'admins', isAdmin: false, roles: [{ id: 1 }] },
    payload: { find: async () => ({ docs: [{ permissions: [{ collections: ['*'], read: true }] }] }) },
  }
  assert.equal(await hasPermission(req as never, 'media', 'read'), true)
  assert.equal(await hasPermission(req as never, 'site-settings', 'read'), true)
  assert.equal(await hasPermission(req as never, 'media', 'update'), false)
})

test('autoAccess fills undefined ops by default, false opts out', async () => {
  const openRead = () => true
  const cfg = {
    admin: { user: 'admins' },
    collections: [
      col('admins', true),
      // no access -> all four ops filled
      col('media'),
      // read defined -> untouched
      col('pages', false, { read: openRead }),
    ],
    globals: [glob('site-settings')],
  }
  const out = await Promise.resolve(roleAccessPlugin()(cfg as unknown as Incoming))
  const media = out.collections!.find((c) => c.slug === 'media')!
  const pages = out.collections!.find((c) => c.slug === 'pages')!
  const settings = out.globals!.find((g) => g.slug === 'site-settings')!
  assert.deepEqual(Object.keys(media.access as object).sort(), [
    'create',
    'delete',
    'read',
    'update',
  ])
  assert.equal((pages.access as Record<string, unknown>).read, openRead)
  // globals only get read/update
  assert.deepEqual(Object.keys(settings.access as object).sort(), ['read', 'update'])

  const outOff = await Promise.resolve(
    roleAccessPlugin({ autoAccess: false })(cfg as unknown as Incoming),
  )
  assert.equal(outOff.collections!.find((c) => c.slug === 'media')!.access, undefined)
})
