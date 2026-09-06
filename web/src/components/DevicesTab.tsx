import { useState, useMemo, useEffect } from 'react'
import {
  Search,
  Laptop,
  ArrowDown,
  ArrowUp,
  Network,
  ChevronRight,
  HelpCircle,
  Globe,
  HardDrive,
  Clock,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from './ui/card'
import { Input } from './ui/input'
import { Badge } from './ui/badge'
import { Tabs, TabsList, TabsTrigger } from './ui/tabs'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table'
import { cn } from '@/lib/utils'
import {
  formatBytes,
  formatRate,
  formatPacketsRate,
  formatRelativeTime,
} from '@/lib/format'
import { rpcClient } from '@/lib/client'
import { DeviceDetailModal } from './DeviceDetailModal'

interface DevicesTabProps {
  devices: any[]
}

export function DevicesTab({ devices }: DevicesTabProps) {
  const [search, setSearch] = useState('')
  const [selectedInterface, setSelectedInterface] = useState<string>('all')
  const [statusFilter, setStatusFilter] = useState<'all' | 'active' | 'offline'>('all')
  const [trafficScope, setTrafficScope] = useState<'total' | 'wan' | 'lan' | 'split'>('total')
  const [period, setPeriod] = useState<'15m' | '1h' | '6h' | '24h'>('1h')
  const [selectedDevice, setSelectedDevice] = useState<any | null>(null)

  const [periodDevices, setPeriodDevices] = useState<any[] | null>(null)
  const [periodLoading, setPeriodLoading] = useState(false)

  // Fetch period-aggregated device usage from TSDB every 5 seconds
  useEffect(() => {
    let active = true
    async function fetchPeriodData() {
      setPeriodLoading(true)
      try {
        const now = Math.floor(Date.now() / 1000)
        let from = now - 3600
        if (period === '15m') from = now - 900
        else if (period === '6h') from = now - 21600
        else if (period === '24h') from = now - 86400

        const res = await rpcClient.listDevices({
          fromUnix: BigInt(from),
          toUnix: BigInt(now),
        })
        if (active) {
          setPeriodDevices(res.devices || [])
        }
      } catch (err) {
        console.error('Failed to fetch period devices:', err)
      } finally {
        if (active) setPeriodLoading(false)
      }
    }

    fetchPeriodData()
    const interval = setInterval(fetchPeriodData, 5000)
    return () => {
      active = false
      clearInterval(interval)
    }
  }, [period])

  const activeDeviceList = periodDevices !== null ? periodDevices : devices

  // Extract unique interface names
  const interfaces = useMemo(() => {
    const set = new Set<string>()
    for (const d of activeDeviceList) {
      set.add(d.device || 'lan')
    }
    return Array.from(set).sort()
  }, [activeDeviceList])

  // Count devices per interface
  const interfaceCounts = useMemo(() => {
    const counts: Record<string, number> = {}
    for (const d of activeDeviceList) {
      const iface = d.device || 'lan'
      counts[iface] = (counts[iface] || 0) + 1
    }
    return counts
  }, [activeDeviceList])

  // Count devices by status
  const statusCounts = useMemo(() => {
    let active = 0
    let offline = 0
    for (const d of activeDeviceList) {
      const s = d.status || (d.isValid ? 'active' : 'unreachable')
      if (s === 'active' || s === 'static') {
        active++
      } else if (s === 'offline') {
        offline++
      }
    }
    return { active, offline, all: activeDeviceList.length }
  }, [activeDeviceList])

  // Fallback to 'all' if selected interface is no longer present
  const currentInterface =
    selectedInterface === 'all' || interfaces.includes(selectedInterface)
      ? selectedInterface
      : 'all'

  const filtered = useMemo(() => {
    return activeDeviceList.filter((d) => {
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
  }, [activeDeviceList, currentInterface, statusFilter, search])

  const totalDl = activeDeviceList.reduce((acc, d) => acc + Number(d.periodDownloadBytes || 0), 0)
  const totalUl = activeDeviceList.reduce((acc, d) => acc + Number(d.periodUploadBytes || 0), 0)
  const filteredDl = filtered.reduce((acc, d) => acc + Number(d.periodDownloadBytes || 0), 0)
  const filteredUl = filtered.reduce((acc, d) => acc + Number(d.periodUploadBytes || 0), 0)

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
                Inspect real-time rates (bytes/s & pps) and period-accurate bandwidth from SQLite TSDB. Click any row for details.
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
            <div className="flex flex-wrap items-center gap-3">
              {/* Status Filter */}
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

              {/* Traffic Scope Toggle */}
              <div className="flex items-center gap-2">
                <span className="text-xs font-medium text-muted-foreground shrink-0">Traffic Scope:</span>
                <Tabs value={trafficScope} onValueChange={(v: any) => setTrafficScope(v)} className="shrink-0">
                  <TabsList className="h-8">
                    <TabsTrigger value="total" className="text-xs px-2.5 py-1 flex items-center gap-1.5">
                      <HardDrive className="w-3 h-3" />
                      <span>Total</span>
                    </TabsTrigger>
                    <TabsTrigger value="wan" className="text-xs px-2.5 py-1 flex items-center gap-1.5">
                      <Globe className="w-3 h-3 text-emerald-500" />
                      <span>WAN (Internet)</span>
                    </TabsTrigger>
                    <TabsTrigger value="lan" className="text-xs px-2.5 py-1 flex items-center gap-1.5">
                      <Network className="w-3 h-3 text-blue-500" />
                      <span>LAN (Local)</span>
                    </TabsTrigger>
                    <TabsTrigger value="split" className="text-xs px-2.5 py-1">
                      All (Split)
                    </TabsTrigger>
                  </TabsList>
                </Tabs>
              </div>

              {/* Period Selector */}
              <div className="flex items-center gap-2">
                <span className="text-xs font-medium text-muted-foreground shrink-0 flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  Period:
                </span>
                <Tabs value={period} onValueChange={(v: any) => setPeriod(v)} className="shrink-0">
                  <TabsList className="h-8">
                    <TabsTrigger value="15m" className="text-xs px-2.5 py-1">
                      15m
                    </TabsTrigger>
                    <TabsTrigger value="1h" className="text-xs px-2.5 py-1">
                      1h
                    </TabsTrigger>
                    <TabsTrigger value="6h" className="text-xs px-2.5 py-1">
                      6h
                    </TabsTrigger>
                    <TabsTrigger value="24h" className="text-xs px-2.5 py-1">
                      24h
                    </TabsTrigger>
                  </TabsList>
                </Tabs>
                {periodLoading && (
                  <span className="text-[11px] text-muted-foreground animate-pulse">Loading...</span>
                )}
              </div>
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
                        {activeDeviceList.length}
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
          <div className="rounded-md border overflow-x-auto">
            <Table>
              <TableHeader>
                {trafficScope !== 'split' ? (
                  <TableRow>
                    <TableHead>Hostname / Name</TableHead>
                    <TableHead>IP Address</TableHead>
                    <TableHead>MAC Address</TableHead>
                    <TableHead>Interface</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="text-right">
                      <span className="inline-flex items-center gap-1">
                        Current Rate {trafficScope === 'wan' ? '(WAN)' : trafficScope === 'lan' ? '(LAN)' : '(Total)'}
                      </span>
                    </TableHead>
                    <TableHead className="text-right">
                      <span className="inline-flex items-center gap-1">
                        Bandwidth Used ({period})
                      </span>
                    </TableHead>
                    <TableHead className="w-8"></TableHead>
                  </TableRow>
                ) : (
                  <TableRow>
                    <TableHead>Hostname / Name</TableHead>
                    <TableHead>IP Address</TableHead>
                    <TableHead>MAC Address</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="text-right">
                      <span className="inline-flex items-center gap-1 text-emerald-600 dark:text-emerald-400">
                        <Globe className="w-3.5 h-3.5" /> WAN ({period})
                      </span>
                    </TableHead>
                    <TableHead className="text-right">
                      <span className="inline-flex items-center gap-1 text-blue-600 dark:text-blue-400">
                        <Network className="w-3.5 h-3.5" /> LAN ({period})
                      </span>
                    </TableHead>
                    <TableHead className="text-right">
                      <span className="inline-flex items-center gap-1">
                        <HardDrive className="w-3.5 h-3.5" /> Total ({period})
                      </span>
                    </TableHead>
                    <TableHead className="w-8"></TableHead>
                  </TableRow>
                )}
              </TableHeader>
              <TableBody>
                {filtered.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={trafficScope === 'split' ? 8 : 8} className="h-24 text-center text-muted-foreground">
                      {activeDeviceList.length === 0
                        ? "No devices detected or stored yet."
                        : currentInterface !== 'all' && !search
                          ? `No devices detected on interface "${currentInterface}".`
                          : "No devices matching filter criteria."}
                    </TableCell>
                  </TableRow>
                ) : (
                  filtered.map((device, idx) => {
                    const status = device.status || (device.isValid ? 'active' : 'unreachable')
                    const isOnline = status === 'active' || status === 'static'

                    // Rate metrics
                    const totalDlRate = Number(device.currentDownloadBytesPerSec || 0)
                    const totalUlRate = Number(device.currentUploadBytesPerSec || 0)
                    const totalDlPktsRate = Number(device.currentDownloadPacketsPerSec || 0)
                    const totalUlPktsRate = Number(device.currentUploadPacketsPerSec || 0)

                    const wanDlRate = Number(device.currentWanDownloadBytesPerSec || 0)
                    const wanUlRate = Number(device.currentWanUploadBytesPerSec || 0)
                    const wanDlPktsRate = Number(device.currentWanDownloadPacketsPerSec || 0)
                    const wanUlPktsRate = Number(device.currentWanUploadPacketsPerSec || 0)

                    const lanDlRate = Number(device.currentLanDownloadBytesPerSec || 0)
                    const lanUlRate = Number(device.currentLanUploadBytesPerSec || 0)
                    const lanDlPktsRate = Number(device.currentLanDownloadPacketsPerSec || 0)
                    const lanUlPktsRate = Number(device.currentLanUploadPacketsPerSec || 0)

                    // Period volume metrics (queried from TSDB samples for the selected period)
                    const periodDlBytes = Number(device.periodDownloadBytes || 0)
                    const periodUlBytes = Number(device.periodUploadBytes || 0)
                    const periodWanDlBytes = Number(device.periodWanDownloadBytes || 0)
                    const periodWanUlBytes = Number(device.periodWanUploadBytes || 0)
                    const periodLanDlBytes = Number(device.periodLanDownloadBytes || 0)
                    const periodLanUlBytes = Number(device.periodLanUploadBytes || 0)

                    // Active metrics for scoped view
                    let activeDlRate = totalDlRate
                    let activeUlRate = totalUlRate
                    let activeDlPktsRate = totalDlPktsRate
                    let activeUlPktsRate = totalUlPktsRate

                    let activeDlBytes = periodDlBytes
                    let activeUlBytes = periodUlBytes

                    if (trafficScope === 'wan') {
                      activeDlRate = wanDlRate
                      activeUlRate = wanUlRate
                      activeDlPktsRate = wanDlPktsRate
                      activeUlPktsRate = wanUlPktsRate
                      activeDlBytes = periodWanDlBytes
                      activeUlBytes = periodWanUlBytes
                    } else if (trafficScope === 'lan') {
                      activeDlRate = lanDlRate
                      activeUlRate = lanUlRate
                      activeDlPktsRate = lanDlPktsRate
                      activeUlPktsRate = lanUlPktsRate
                      activeDlBytes = periodLanDlBytes
                      activeUlBytes = periodLanUlBytes
                    }

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
                        {trafficScope !== 'split' && (
                          <TableCell className="font-mono text-xs">
                            <Badge variant="outline">{device.device || 'lan'}</Badge>
                          </TableCell>
                        )}
                        <TableCell>
                          <div className="flex flex-col items-start gap-1">
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
                          </div>
                        </TableCell>

                        {trafficScope !== 'split' ? (
                          <>
                            {/* Current Rate Column */}
                            <TableCell className="text-right font-mono">
                              {isOnline && (activeDlRate > 0 || activeUlRate > 0) ? (
                                <div className="flex flex-col items-end gap-0.5">
                                  <span className="text-emerald-600 dark:text-emerald-400 font-medium text-xs flex items-center gap-1">
                                    <ArrowDown className="w-3 h-3 text-emerald-500" />
                                    {formatRate(activeDlRate)}
                                    <span className="text-[10px] text-muted-foreground font-sans">
                                      ({formatPacketsRate(activeDlPktsRate)})
                                    </span>
                                  </span>
                                  <span className="text-sky-600 dark:text-sky-400 font-medium text-xs flex items-center gap-1">
                                    <ArrowUp className="w-3 h-3 text-sky-500" />
                                    {formatRate(activeUlRate)}
                                    <span className="text-[10px] text-muted-foreground font-sans">
                                      ({formatPacketsRate(activeUlPktsRate)})
                                    </span>
                                  </span>
                                </div>
                              ) : (
                                <span className="text-muted-foreground/50 text-xs">Idle</span>
                              )}
                            </TableCell>

                            {/* Bandwidth Used Column */}
                            <TableCell className="text-right font-mono">
                              <div className="flex flex-col items-end gap-0.5">
                                <span className="text-foreground font-semibold text-xs flex items-center gap-1">
                                  <span className="text-emerald-500 font-bold">↓</span>
                                  {formatBytes(activeDlBytes)}
                                </span>
                                <span className="text-foreground font-semibold text-xs flex items-center gap-1">
                                  <span className="text-sky-500 font-bold">↑</span>
                                  {formatBytes(activeUlBytes)}
                                </span>
                                {trafficScope === 'total' && (periodWanDlBytes + periodWanUlBytes > 0 || periodLanDlBytes + periodLanUlBytes > 0) && (
                                  <span className="text-[10px] text-muted-foreground/80 flex items-center gap-1 mt-0.5 font-sans">
                                    <span className="text-emerald-600 dark:text-emerald-400">WAN {formatBytes(periodWanDlBytes + periodWanUlBytes)}</span>
                                    <span>•</span>
                                    <span className="text-blue-600 dark:text-blue-400">LAN {formatBytes(periodLanDlBytes + periodLanUlBytes)}</span>
                                  </span>
                                )}
                              </div>
                            </TableCell>
                          </>
                        ) : (
                          <>
                            {/* WAN Column */}
                            <TableCell className="text-right font-mono">
                              <div className="flex flex-col items-end gap-0.5">
                                <div className="text-xs font-semibold text-foreground">
                                  ↓ {formatBytes(periodWanDlBytes)} ↑ {formatBytes(periodWanUlBytes)}
                                </div>
                                {(wanDlRate > 0 || wanUlRate > 0) ? (
                                  <div className="text-[10px] text-emerald-600 dark:text-emerald-400 font-medium">
                                    Rate: ↓{formatRate(wanDlRate)} ↑{formatRate(wanUlRate)}
                                  </div>
                                ) : (
                                  <div className="text-[10px] text-muted-foreground/60">
                                    Idle
                                  </div>
                                )}
                              </div>
                            </TableCell>

                            {/* LAN Column */}
                            <TableCell className="text-right font-mono">
                              <div className="flex flex-col items-end gap-0.5">
                                <div className="text-xs font-semibold text-foreground">
                                  ↓ {formatBytes(periodLanDlBytes)} ↑ {formatBytes(periodLanUlBytes)}
                                </div>
                                {(lanDlRate > 0 || lanUlRate > 0) ? (
                                  <div className="text-[10px] text-blue-600 dark:text-blue-400 font-medium">
                                    Rate: ↓{formatRate(lanDlRate)} ↑{formatRate(lanUlRate)}
                                  </div>
                                ) : (
                                  <div className="text-[10px] text-muted-foreground/60">
                                    Idle
                                  </div>
                                )}
                              </div>
                            </TableCell>

                            {/* Total Column */}
                            <TableCell className="text-right font-mono">
                              <div className="flex flex-col items-end gap-0.5">
                                <div className="text-xs font-semibold text-foreground">
                                  ↓ {formatBytes(periodDlBytes)} ↑ {formatBytes(periodUlBytes)}
                                </div>
                                {(totalDlRate > 0 || totalUlRate > 0) ? (
                                  <div className="text-[10px] text-primary font-medium">
                                    Rate: ↓{formatRate(totalDlRate)} ↑{formatRate(totalUlRate)}
                                  </div>
                                ) : (
                                  <div className="text-[10px] text-muted-foreground/60">
                                    Idle
                                  </div>
                                )}
                              </div>
                            </TableCell>
                          </>
                        )}

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
              Showing {filtered.length} of {activeDeviceList.length} {activeDeviceList.length === 1 ? 'device' : 'devices'}
              {currentInterface !== 'all' && ` (interface: ${currentInterface})`}
              {statusFilter !== 'all' && ` (${statusFilter})`}
              {trafficScope !== 'total' && ` [Scope: ${trafficScope.toUpperCase()}]`}
              {` [Period: ${period}]`}
            </span>
            <span>
              Total Volume ({period}): <span className="font-semibold text-foreground">{formatBytes(totalDl + totalUl)}</span>
              {filtered.length < activeDeviceList.length && (
                <span className="ml-1.5 text-muted-foreground">
                  (Filtered: <strong className="text-foreground">{formatBytes(filteredDl + filteredUl)}</strong>)
                </span>
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
