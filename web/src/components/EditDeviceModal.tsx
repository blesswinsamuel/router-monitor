import { useState, useEffect } from 'react'
import { X, Plus, Trash2, Check, Tag, AlertCircle } from 'lucide-react'
import { Button } from './ui/button'
import { Input } from './ui/input'
import { Badge } from './ui/badge'
import { rpcClient } from '@/lib/client'
import type { Device } from '@/gen/routermonitor/v1/router_monitor_pb'

interface EditDeviceModalProps {
  isOpen: boolean
  onClose: () => void
  device?: Device | null
  onSaved: () => void
}

const COMMON_TAGS = ['allow_internet', 'cast_target', 'kiosk']
const COMMON_VLANS = ['trusted', 'iot', 'cameras', 'management', 'guest', 'lan']

export function EditDeviceModal({ isOpen, onClose, device, onSaved }: EditDeviceModalProps) {
  const [name, setName] = useState('')
  const [mac, setMac] = useState('')
  const [ip, setIp] = useState('')
  const [vlan, setVlan] = useState('')
  const [hostnamesStr, setHostnamesStr] = useState('')
  const [tags, setTags] = useState<string[]>([])
  const [newTagInput, setNewTagInput] = useState('')
  const [isSaving, setIsSaving] = useState(false)
  const [isDeleting, setIsDeleting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const isConfigured = Boolean(device?.isConfigured || device?.configId || device?.configName)

  useEffect(() => {
    if (!isOpen) return

    if (device) {
      setName(device.configName || device.hostname || '')
      setMac(device.macAddr || '')
      setIp(device.ipAddr || '')
      setVlan(device.vlan || 'trusted')
      setHostnamesStr(
        device.configHostnames && device.configHostnames.length > 0
          ? device.configHostnames.join(', ')
          : device.hostname || ''
      )
      setTags(device.tags ? [...device.tags] : [])
    } else {
      setName('')
      setMac('')
      setIp('')
      setVlan('trusted')
      setHostnamesStr('')
      setTags([])
    }
    setNewTagInput('')
    setError(null)
  }, [isOpen, device])

  if (!isOpen) return null

  const handleAddTag = (tagToAdd?: string) => {
    const t = (tagToAdd || newTagInput).trim().toLowerCase()
    if (!t) return
    if (!tags.includes(t)) {
      setTags([...tags, t])
    }
    setNewTagInput('')
  }

  const handleRemoveTag = (tagToRemove: string) => {
    setTags(tags.filter((t) => t !== tagToRemove))
  }

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)

    if (!mac.trim() && !ip.trim()) {
      setError('At least a MAC or IP address is required.')
      return
    }

    setIsSaving(true)
    try {
      const hostnames = hostnamesStr
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)

      const id = device?.configId || (name ? name.toLowerCase().replace(/[^a-z0-9_-]/g, '-') : mac.replace(/:/g, '-'))

      await rpcClient.upsertConfigDevice({
        device: {
          $typeName: 'routermonitor.v1.ConfigDevice',
          id,
          name: name.trim(),
          mac: mac.trim().toLowerCase(),
          vlan: vlan.trim().toLowerCase(),
          ip: ip.trim(),
          hostnames,
          tags,
        },
      })
      onSaved()
      onClose()
    } catch (err: any) {
      setError(err?.message || 'Failed to save device reservation')
    } finally {
      setIsSaving(false)
    }
  }

  const handleDelete = async () => {
    const id = device?.configId || (name ? name.toLowerCase().replace(/[^a-z0-9_-]/g, '-') : mac.replace(/:/g, '-'))
    if (!id) return
    if (!window.confirm(`Are you sure you want to remove reservation for "${name || mac || id}"?`)) {
      return
    }

    setIsDeleting(true)
    try {
      await rpcClient.deleteConfigDevice({ id })
      onSaved()
      onClose()
    } catch (err: any) {
      setError(err?.message || 'Failed to delete device reservation')
    } finally {
      setIsDeleting(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs animate-in fade-in duration-150">
      <div
        className="relative w-full max-w-lg rounded-xl border bg-card p-6 shadow-xl text-card-foreground flex flex-col max-h-[90vh] overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        <button
          onClick={onClose}
          className="absolute right-4 top-4 rounded-sm opacity-70 hover:opacity-100 transition-opacity"
        >
          <X className="h-4 w-4" />
        </button>

        <div className="mb-4">
          <h3 className="text-lg font-semibold tracking-tight">
            {isConfigured ? 'Edit Device Reservation' : 'Configure DHCP Reservation'}
          </h3>
          <p className="text-xs text-muted-foreground mt-0.5">
            Reservations are saved directly to <code className="bg-muted px-1 rounded text-foreground font-mono">devices.yaml</code> and reloaded into dnsmasq and nftables immediately.
          </p>
        </div>

        {error && (
          <div className="mb-4 flex items-center gap-2 rounded-md bg-destructive/10 p-3 text-xs text-destructive">
            <AlertCircle className="h-4 w-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSave} className="space-y-4 text-sm">
          <div>
            <label className="block text-xs font-medium text-foreground mb-1">Friendly Name</label>
            <Input
              placeholder="e.g. Living Room Apple TV"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-foreground mb-1">MAC Address</label>
              <Input
                placeholder="00:11:22:33:44:55"
                value={mac}
                onChange={(e) => setMac(e.target.value)}
                className="font-mono text-xs"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-foreground mb-1">IP Address</label>
              <Input
                placeholder="10.100.1.50"
                value={ip}
                onChange={(e) => setIp(e.target.value)}
                className="font-mono text-xs"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-foreground mb-1">VLAN</label>
              <div className="flex gap-1.5 flex-wrap mb-1.5">
                {COMMON_VLANS.map((v) => (
                  <button
                    key={v}
                    type="button"
                    onClick={() => setVlan(v)}
                    className={`text-[10px] px-1.5 py-0.5 rounded border transition-colors ${
                      vlan === v
                        ? 'bg-primary text-primary-foreground border-primary font-semibold'
                        : 'bg-muted text-muted-foreground hover:bg-muted/80'
                    }`}
                  >
                    {v}
                  </button>
                ))}
              </div>
              <Input
                placeholder="trusted, iot, etc."
                value={vlan}
                onChange={(e) => setVlan(e.target.value)}
                className="font-mono text-xs"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-foreground mb-1">Hostnames</label>
              <p className="text-[10px] text-muted-foreground mb-1.5">Comma-separated aliases for DNS</p>
              <Input
                placeholder="apple-tv, living-room"
                value={hostnamesStr}
                onChange={(e) => setHostnamesStr(e.target.value)}
                className="font-mono text-xs"
              />
            </div>
          </div>

          {/* Tags */}
          <div>
            <label className="block text-xs font-medium text-foreground mb-1 flex items-center gap-1.5">
              <Tag className="w-3.5 h-3.5 text-primary" />
              Tags & Firewall Set Memberships
            </label>
            <p className="text-[10px] text-muted-foreground mb-2">
              Common tags map to nftables sets (e.g. <code className="bg-muted px-1 rounded">allow_internet</code>, <code className="bg-muted px-1 rounded">cast_target</code>, <code className="bg-muted px-1 rounded">kiosk</code>).
            </p>

            <div className="flex flex-wrap gap-1.5 mb-2">
              {COMMON_TAGS.map((commonTag) => {
                const isSelected = tags.includes(commonTag)
                return (
                  <button
                    key={commonTag}
                    type="button"
                    onClick={() => (isSelected ? handleRemoveTag(commonTag) : handleAddTag(commonTag))}
                    className={`text-xs px-2 py-0.5 rounded-full border transition-colors flex items-center gap-1 ${
                      isSelected
                        ? 'bg-primary/20 text-primary border-primary/40 font-medium'
                        : 'bg-muted text-muted-foreground hover:text-foreground'
                    }`}
                  >
                    {isSelected && <Check className="w-3 h-3" />}
                    <span>{commonTag}</span>
                  </button>
                )
              })}
            </div>

            <div className="flex gap-2">
              <Input
                placeholder="Custom tag (e.g. server, lab)..."
                value={newTagInput}
                onChange={(e) => setNewTagInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault()
                    handleAddTag()
                  }
                }}
                className="text-xs"
              />
              <Button type="button" variant="outline" size="sm" onClick={() => handleAddTag()}>
                <Plus className="w-3.5 h-3.5" />
              </Button>
            </div>

            {tags.length > 0 && (
              <div className="flex flex-wrap gap-1.5 mt-2.5 p-2 rounded-md bg-muted/40 border">
                {tags.map((t) => (
                  <Badge key={t} variant="secondary" className="gap-1 text-xs px-2 py-0.5">
                    <span>{t}</span>
                    <button
                      type="button"
                      onClick={() => handleRemoveTag(t)}
                      className="hover:text-destructive transition-colors ml-0.5"
                    >
                      <X className="w-3 h-3" />
                    </button>
                  </Badge>
                ))}
              </div>
            )}
          </div>

          <div className="flex items-center justify-between pt-4 border-t mt-6">
            {isConfigured ? (
              <Button
                type="button"
                variant="destructive"
                size="sm"
                onClick={handleDelete}
                disabled={isDeleting || isSaving}
                className="gap-1.5"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>{isDeleting ? 'Deleting...' : 'Delete Reservation'}</span>
              </Button>
            ) : (
              <div />
            )}

            <div className="flex items-center gap-2">
              <Button type="button" variant="outline" size="sm" onClick={onClose} disabled={isSaving}>
                Cancel
              </Button>
              <Button type="submit" size="sm" disabled={isSaving || isDeleting} className="gap-1.5">
                <Check className="w-3.5 h-3.5" />
                <span>{isSaving ? 'Saving...' : 'Save & Apply'}</span>
              </Button>
            </div>
          </div>
        </form>
      </div>
    </div>
  )
}
