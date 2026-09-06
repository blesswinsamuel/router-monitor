import { useState, useMemo } from 'react'
import { Search, Laptop, ArrowDown, ArrowUp, Network, Activity, ChevronRight, HelpCircle } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from './ui/card'
import { Input } from './ui/input'
import { Badge } from './ui/badge'
import { Tabs, TabsList, TabsTrigger } from './ui/tabs'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table'
import { cn } from '@/lib/utils'
import { formatBytes, formatPackets, formatRate, formatRelativeTime } from '@/lib/format'
import { DeviceDetailModal } from './DeviceDetailModal'

interface DevicesTabProps {
  devices: any[]
}

export function DevicesTab({ devices }: DevicesTabProps) {
  const [search, setSearch] = useState('')
  const [selectedInterface, setSelectedInterface] = useState<string>('all')
  const [statusFilter, setStatusFilter] = useState<'all' | 'active' | 'offline'>('all')
  const [selectedDevice, setSelectedDevice] = useState<any | null>(null)

  // Extract unique interface names
  const interfaces = useMemo(() => {
    const set = new Set<string>()
    for (const d of devices) {
      set.add(d.device || 'lan')
    }
    return Array.from(set).sort()
  }, [devices])

  // Count devices per interface
  const interfaceCounts = useMemo(() => {
    const counts: Record<string, number> = {}
    for (const d of devices) {
      const iface = d.device || 'lan'
      counts[iface] = (counts[iface] || 0) + 1
    }
    return counts
  }, [devices])

  // Count devices by status
  const statusCounts = useMemo(() => {
    let active = 0
    let offline = 0
    for (const d of devices) {
      const s = d.status || (d.isValid ? 'active' : 'unreachable')
      if (s === 'active' || s === 'static') {
        active++
      } else if (s === 'offline') {
        offline++
      }
    }
    return { active, offline, all: devices.length }
  }, [devices])

  // Fallback to 'all' if selected interface is no longer present
  const currentInterface =
    selectedInterface === 'all' || interfaces.includes(selectedInterface)
      ? selectedInterface
      : 'all'

  const filtered = useMemo(() => {
    return devices.filter((d) => {
      const iface = d.device || 'lan'
      if (currentInterface !== 'all' && iface !== currentInterface) {
        return false
      }

      const s = d.status || (d.isValid ? 'active' : 'unreachable')
      if (statusFilter === 'active' && s !== 'active' && s !== 'static') {
        return false
      }
      if (statusFilter === 'offline' && s !== 'offline') {
        return false
      }

      if (!search.trim()) return true
      const q = search.toLowerCase()
      return (
        d.hostname?.toLowerCase().includes(q) ||
        d.ipAddr?.toLowerCase().includes(q) ||
        d.hwAddr?.toLowerCase().includes(q) ||
        d.device?.toLowerCase().includes(q)
      )
    })
  }, [devices, currentInterface, statusFilter, search])

  const totalDl = devices.reduce((acc, d) => acc + Number(d.downloadBytes || 0), 0)
  const totalUl = devices.reduce((acc, d) => acc + Number(d.uploadBytes || 0), 0)

  const filteredDl = filtered.reduce((acc, d) => acc + Number(d.downloadBytes || 0), 0)
  const filteredUl = filtered.reduce((acc, d) => acc + Number(d.uploadBytes || 0), 0)

  return (
    <>
      <Card>
        <CardHeader className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Laptop className="w-5 h-5 text-primary" />
                Connected & Discovered Devices
              </CardTitle>
              <CardDescription>
                Real-time and persisted devices with separate WAN vs LAN traffic accounting. Click any row for history.
              </CardDescription>
            </div>
            <div className="relative w-full sm:w-72">
              <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Filter by IP, MAC, Hostname..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-8 text-sm"
              />
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t">
            {/* Status Tabs */}
            <div className="flex items-center gap-2">
              <span className="text-xs font-medium text-muted-foreground shrink-0">Status:</span>
              <Tabs value={statusFilter} onValueChange={(v: any) => setStatusFilter(v)} className="shrink-0">
                <TabsList className="h-8">
                  <TabsTrigger value="all" className="text-xs px-2.5 py-1">
                    All ({statusCounts.all})
                  </TabsTrigger>
                  <TabsTrigger value="active" className="text-xs px-2.5 py-1">
                    Active ({statusCounts.active})
                  </TabsTrigger>
                  {statusCounts.offline > 0 && (
                    <TabsTrigger value="offline" className="text-xs px-2.5 py-1">
                      Offline ({statusCounts.offline})
                    </TabsTrigger>
                  )}
                </TabsList>
              </Tabs>
            </div>

            {/* Interface Tabs */}
            {interfaces.length > 1 && (
              <div className="flex items-center gap-2 overflow-x-auto pb-0.5">
                <div className="text-xs font-medium text-muted-foreground flex items-center gap-1.5 shrink-0">
                  <Network className="w-3.5 h-3.5" />
                  <span>Interface:</span>
                </div>
                <Tabs value={currentInterface} onValueChange={setSelectedInterface} className="shrink-0">
                  <TabsList className="h-8">
                    <TabsTrigger value="all" className="text-xs px-2.5 py-1 flex items-center gap-1.5">
                      <span>All</span>
                      <span
                        className={cn(
                          "px-1.5 py-0.2 rounded-full text-[10px] font-mono",
                          currentInterface === 'all'
                            ? "bg-primary/15 text-primary font-semibold"
                            : "bg-muted-foreground/15 text-muted-foreground"
                        )}
                      >
                        {devices.length}
                      </span>
                    </TabsTrigger>
                    {interfaces.map((iface) => (
                      <TabsTrigger
                        key={iface}
                        value={iface}
                        className="text-xs px-2.5 py-1 flex items-center gap-1.5"
                      >
                        <span>{iface}</span>
                        <span
                          className={cn(
                            "px-1.5 py-0.2 rounded-full text-[10px] font-mono",
                            currentInterface === iface
                              ? "bg-primary/15 text-primary font-semibold"
                              : "bg-muted-foreground/15 text-muted-foreground"
                          )}
                        >
                          {interfaceCounts[iface] || 0}
                        </span>
                      </TabsTrigger>
                    ))}
                  </TabsList>
                </Tabs>
              </div>
            )}
          </div>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Hostname / Name</TableHead>
                  <TableHead>IP Address</TableHead>
                  <TableHead>MAC Address</TableHead>
                  <TableHead>Interface</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">
                    <span className="inline-flex items-center gap-1">
                      <ArrowDown className="w-3.5 h-3.5 text-emerald-500" /> Download
                    </span>
                  </TableHead>
                  <TableHead className="text-right">
                    <span className="inline-flex items-center gap-1">
                      <ArrowUp className="w-3.5 h-3.5 text-sky-500" /> Upload
                    </span>
                  </TableHead>
                  <TableHead className="w-8"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={8} className="h-24 text-center text-muted-foreground">
                      {devices.length === 0
                        ? "No devices detected or stored yet."
                        : currentInterface !== 'all' && !search
                          ? `No devices detected on interface "${currentInterface}".`
                          : "No devices matching filter criteria."}
                    </TableCell>
                  </TableRow>
                ) : (
                  filtered.map((device, idx) => {
                    const dl = Number(device.downloadBytes || 0)
                    const dlPct = totalDl > 0 ? (dl / totalDl) * 100 : 0
                    const status = device.status || (device.isValid ? 'active' : 'unreachable')
                    const isOnline = status === 'active' || status === 'static'
                    const dlRate = Number(device.currentDownloadBytesPerSec || 0)
                    const ulRate = Number(device.currentUploadBytesPerSec || 0)

                    const internetDl = Number(device.internetDownloadBytes || 0)
                    const lanDl = Number(device.lanDownloadBytes || 0)
                    const internetUl = Number(device.internetUploadBytes || 0)
                    const lanUl = Number(device.lanUploadBytes || 0)

                    return (
                      <TableRow
                        key={`${device.ipAddr}-${idx}`}
                        onClick={() => setSelectedDevice(device)}
                        className="cursor-pointer hover:bg-muted/40 transition-colors group"
                      >
                        <TableCell className="font-medium">
                          <div className="flex flex-col">
                            <span className="font-semibold text-foreground group-hover:text-primary transition-colors flex items-center gap-1.5">
                              {device.hostname && !device.hostname.startsWith('unknown:')
                                ? device.hostname
                                : 'Unknown Device'}
                            </span>
                            <span className="text-xs text-muted-foreground font-mono">
                              {device.ipAddr}
                            </span>
                          </div>
                        </TableCell>
                        <TableCell className="font-mono text-xs">{device.ipAddr}</TableCell>
                        <TableCell className="font-mono text-xs text-muted-foreground">{device.hwAddr}</TableCell>
                        <TableCell className="font-mono text-xs">
                          <Badge variant="outline">{device.device || 'lan'}</Badge>
                        </TableCell>
                        <TableCell>
                          <div className="flex flex-col items-start gap-0.5">
                            {status === 'active' && (
                              <Badge
                                variant="outline"
                                className="text-[11px] border-emerald-500/20 bg-emerald-500/15 text-emerald-600 dark:text-emerald-400"
                              >
                                Active
                              </Badge>
                            )}
                            {status === 'static' && (
                              <Badge
                                variant="outline"
                                className="text-[11px] border-sky-500/20 bg-sky-500/15 text-sky-600 dark:text-sky-400"
                              >
                                Static
                              </Badge>
                            )}
                            {status === 'unreachable' && (
                              <Badge
                                variant="secondary"
                                className="text-[11px] border-amber-500/20 bg-amber-500/15 text-amber-600 dark:text-amber-400 cursor-help"
                                title="ARP probe was sent, but no response was received from this IP"
                              >
                                <span className="flex items-center gap-1">
                                  Unreachable
                                  <HelpCircle className="w-2.5 h-2.5 opacity-60" />
                                </span>
                              </Badge>
                            )}
                            {status === 'offline' && (
                              <Badge
                                variant="secondary"
                                className="text-[11px] text-muted-foreground bg-muted"
                              >
                                Offline
                              </Badge>
                            )}
                            {status === 'offline' && device.lastSeenUnix > 0 && (
                              <span className="text-[10px] text-muted-foreground">
                                {formatRelativeTime(device.lastSeenUnix)}
                              </span>
                            )}
                            {isOnline && (dlRate > 0 || ulRate > 0) && (
                              <span className="text-[10px] font-mono text-primary font-medium flex items-center gap-1 mt-0.5">
                                <Activity className="w-2.5 h-2.5 animate-pulse" />
                                {formatRate(dlRate + ulRate)}
                              </span>
                            )}
                          </div>
                        </TableCell>
                        <TableCell className="text-right font-mono">
                          <div className="flex flex-col items-end">
                            <span className="text-emerald-500 font-semibold">{formatBytes(device.downloadBytes)}</span>
                            {(internetDl > 0 || lanDl > 0) ? (
                              <span className="text-[10px] text-muted-foreground flex items-center gap-1">
                                <span>WAN {formatBytes(internetDl)}</span>
                                {lanDl > 0 && (
                                  <>
                                    <span>•</span>
                                    <span>LAN {formatBytes(lanDl)}</span>
                                  </>
                                )}
                              </span>
                            ) : (
                              <span className="text-[10px] text-muted-foreground">
                                {formatPackets(device.downloadPackets)} pkts ({dlPct.toFixed(1)}%)
                              </span>
                            )}
                          </div>
                        </TableCell>
                        <TableCell className="text-right font-mono">
                          <div className="flex flex-col items-end">
                            <span className="text-sky-500 font-semibold">{formatBytes(device.uploadBytes)}</span>
                            {(internetUl > 0 || lanUl > 0) ? (
                              <span className="text-[10px] text-muted-foreground flex items-center gap-1">
                                <span>WAN {formatBytes(internetUl)}</span>
                                {lanUl > 0 && (
                                  <>
                                    <span>•</span>
                                    <span>LAN {formatBytes(lanUl)}</span>
                                  </>
                                )}
                              </span>
                            ) : (
                              <span className="text-[10px] text-muted-foreground">
                                {formatPackets(device.uploadPackets)} pkts
                              </span>
                            )}
                          </div>
                        </TableCell>
                        <TableCell className="text-center p-0 pr-2">
                          <ChevronRight className="w-4 h-4 text-muted-foreground/40 group-hover:text-primary transition-colors" />
                        </TableCell>
                      </TableRow>
                    )
                  })
                )}
              </TableBody>
            </Table>
          </div>
          <div className="mt-4 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs text-muted-foreground px-1">
            <span>
              Showing {filtered.length} of {devices.length} {devices.length === 1 ? 'device' : 'devices'}
              {currentInterface !== 'all' && ` (interface: ${currentInterface})`}
              {statusFilter !== 'all' && ` (${statusFilter})`}
            </span>
            <span>
              {currentInterface !== 'all' ? (
                <>
                  {currentInterface} Volume: <span className="font-semibold text-foreground">{formatBytes(filteredDl + filteredUl)}</span>
                  <span className="ml-1">({formatBytes(totalDl + totalUl)} total)</span>
                </>
              ) : (
                <>
                  Total Volume: <span className="font-semibold text-foreground">{formatBytes(totalDl + totalUl)}</span>
                </>
              )}
            </span>
          </div>
        </CardContent>
      </Card>

      {/* Device Detail & Time Series Modal */}
      <DeviceDetailModal
        device={selectedDevice}
        open={!!selectedDevice}
        onOpenChange={(open) => {
          if (!open) setSelectedDevice(null)
        }}
      />
    </>
  )
}

