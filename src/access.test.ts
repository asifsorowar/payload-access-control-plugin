import assert from 'node:assert/strict'
import { test } from 'node:test'

import type { PayloadRequest } from 'payload'

import { adminOnly, adminOrRole, publicOrGrantedOps, selfOrAdmin, selfOrGranted } from './access.js'

const mockReq = ({ user, docs = [] }: { user?: unknown; docs?: unknown[] }): PayloadRequest =>
  ({ user, payload: { find: async () => ({ docs }) } }) as unknown as PayloadRequest

const grantDoc = (slug: string, op: string) => ({
  permissions: [{ collections: [slug], [op]: true }],
})

test('anonymous read falls back to public docs', async () => {
  const req = mockReq({ user: null })
  assert.deepEqual(await publicOrGrantedOps('media', 'read')({ req }), {
    access: { equals: 'public' },
  })
})

test('superuser bypasses role checks', async () => {
  const req = mockReq({ user: { collection: 'admins', isAdmin: true } })
  assert.equal(await adminOrRole('media', 'delete')({ req }), true)
  assert.equal(await adminOnly({ req }), true)
})

test('anonymous gets nothing', async () => {
  const req = mockReq({ user: null })
  assert.equal(await adminOrRole('media', 'read')({ req }), false)
  assert.equal(await adminOnly({ req }), false)
})

test('role grant passes only the granted op', async () => {
  const req = mockReq({
    user: { collection: 'admins', isAdmin: false, roles: [{ id: 1 }] },
    docs: [grantDoc('media', 'read')],
  })
  assert.equal(await adminOrRole('media', 'read')({ req }), true)
  assert.equal(await adminOrRole('media', 'update')({ req }), false)
})

test('grant on another collection does not leak', async () => {
  const req = mockReq({
    user: { collection: 'admins', isAdmin: false, roles: [{ id: 1 }] },
    docs: [grantDoc('pubmedia', 'read')],
  })
  assert.equal(await adminOrRole('media', 'read')({ req }), false)
})

test('selfOrAdmin: superuser passes, same-collection self gets Where, others denied', async () => {
  const args = (user: unknown) => ({ req: mockReq({ user }) })
  assert.equal(await selfOrAdmin('admins')(args({ id: 1, collection: 'admins', isAdmin: true })), true)
  assert.deepEqual(
    await selfOrAdmin('admins')(args({ id: 5, collection: 'admins', isAdmin: false })),
    { id: { equals: 5 } },
  )
  // users-token on admins doc 5 must NOT match — cross-collection guard
  assert.equal(await selfOrAdmin('admins')(args({ id: 5, collection: 'users', isAdmin: false })), false)
  assert.equal(await selfOrAdmin('admins')(args(null)), false)
})

test('selfOrGranted: role grant, self Where, and neither', async () => {
  const granted = mockReq({
    user: { id: 2, collection: 'users', isAdmin: false, roles: [{ id: 1 }] },
    docs: [grantDoc('users', 'update')],
  })
  assert.equal(await selfOrGranted('users', 'update')({ req: granted }), true)

  const self = mockReq({ user: { id: 7, collection: 'users', isAdmin: false, roles: [] } })
  assert.deepEqual(await selfOrGranted('users', 'update')({ req: self }), { id: { equals: 7 } })

  // no grant, user from another collection → no self match either
  const other = mockReq({ user: { id: 7, collection: 'admins', isAdmin: false, roles: [] } })
  assert.equal(await selfOrGranted('users', 'update')({ req: other }), false)

  assert.equal(await selfOrGranted('users', 'update')({ req: mockReq({ user: null }) }), false)
})
