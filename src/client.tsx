'use client'

import React, { useState } from 'react'

import { CheckboxInput, fieldBaseClass, useField } from '@payloadcms/ui'
import { mergeFieldStyles } from '@payloadcms/ui/shared'

import type { CheckboxField, ClientField } from 'payload'

import type { PermissionOp } from './access.js'

type Props = {
  path?: string
  field?: CheckboxField
  openOps?: Record<string, PermissionOp[]>
}

const WRITE_OPS: PermissionOp[] = ['create', 'update', 'delete']

/** Role permission checkbox — disabled when the op is already open to everyone. */
export const PermissionCheckbox: React.FC<Props> = ({ path = '', field, openOps = {} }) => {
  const op = field?.name as PermissionOp | undefined
  const { value, setValue } = useField<boolean>({ path })
  const siblingPath = path.replace(/[^.]+$/, 'collections')
  const { value: collections } = useField<string[]>({ path: siblingPath })
  const readPath = path.replace(/[^.]+$/, 'read')
  const { value: readValue, setValue: setRead } = useField<boolean>({ path: readPath })

  const [autoRead, setAutoRead] = useState(false)

  const blocked = !!op && (collections ?? []).some((slug) => openOps[slug]?.includes(op))

  // write grants without read are hidden in the panel nav — auto-check read, manual uncheck stays possible
  const onToggle = (e: React.ChangeEvent<HTMLInputElement>) => {
    setValue(e.target.checked)
    if (!op || !WRITE_OPS.includes(op)) return
    if (e.target.checked) {
      if (!readValue) {
        setRead(true)
        setAutoRead(true)
      }
    } else {
      setAutoRead(false)
    }
  }

  return (
    <div
      className={[fieldBaseClass, 'checkbox'].join(' ')}
      style={mergeFieldStyles(field as ClientField)}
    >
      <CheckboxInput
        checked={Boolean(value)}
        readOnly={blocked}
        onToggle={onToggle}
        label={blocked ? `${op} (already open to everyone)` : op}
      />
      {autoRead && (
        <div className="field-description">
          read auto-checked — {op} without read hides collection from the sidebar
        </div>
      )}
    </div>
  )
}
