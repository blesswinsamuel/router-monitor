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
import { useNavigate } from 'react-router-dom'
import { getDeviceCategory } from '@/lib/device-icons'
import type { Device } from '@/gen/routermonitor/v1/router_monitor_pb'

interface DevicesTabProps {
  devices: Device[]
}

export function DevicesTab({ devices }: DevicesTabProps) {
  const [search, setSearch] = useState('')
  const [selectedInterface, setSelectedInterface] = useState<string>('all')
  const [statusFilter, setStatusFilter] = useState<'all' | 'active' | 'offline'>('all')
  const [trafficScope, setTrafficScope] = useState<'total' | 'wan' | 'lan' | 'split'>('total')
  const [period, setPeriod] = useState<'15m' | '1h' | '6h' | '24h'>('1h')
  const navigate = useNavigate()

  const [periodDevices, setPeriodDevices] = useState<Device[] | null>(null)
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
    const interval = setInterval(fetchPeriodData, 30000)
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
      set.add(d.interface || d.arp?.interface || 'lan')
    }
    return Array.from(set).sort()
  }, [activeDeviceList])

  // Count devices per interface
  const interfaceCounts = useMemo(() => {
    const counts: Record<string, number> = {}
    for (const d of activeDeviceList) {
      const iface = d.interface || d.arp?.interface || 'lan'
      counts[iface] = (counts[iface] || 0) + 1
    }
    return counts
  }, [activeDeviceList])

  // Count devices by status
  const statusCounts = useMemo(() => {
    let active = 0
    let offline = 0
    for (const d of activeDeviceList) {
      const s = d.status || (d.arp?.isValid ? 'active' : 'unreachable')
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
      const iface = d.interface || d.arp?.interface || 'lan'
      if (currentInterface !== 'all' && iface !== currentInterface) {
        return false
      }

      const s = d.status || (d.arp?.isValid ? 'active' : 'unreachable')
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
        d.macAddr?.toLowerCase().includes(q) ||
        d.interface?.toLowerCase().includes(q) ||
        d.arp?.interface?.toLowerCase().includes(q)
      )
    })
  }, [activeDeviceList, currentInterface, statusFilter, search])

  const totalDl = activeDeviceList.reduce((acc, d) => acc + Number(d.total?.downloadBytes || 0), 0)
  const totalUl = activeDeviceList.reduce((acc, d) => acc + Number(d.total?.uploadBytes || 0), 0)
  const filteredDl = filtered.reduce((acc, d) => acc + Number(d.total?.downloadBytes || 0), 0)
  const filteredUl = filtered.reduce((acc, d) => acc + Number(d.total?.uploadBytes || 0), 0)

  return (
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
                      All (<span className="font-mono">{statusCounts.all}</span>)
                    </TabsTrigger>
                    <TabsTrigger value="active" className="text-xs px-2.5 py-1">
                      Active (<span className="font-mono">{statusCounts.active}</span>)
                    </TabsTrigger>
                    {statusCounts.offline > 0 && (
                      <TabsTrigger value="offline" className="text-xs px-2.5 py-1">
                        Offline (<span className="font-mono">{statusCounts.offline}</span>)
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
                    <TabsTrigger value="15m" className="text-xs px-2.5 py-1 font-mono">
                      15m
                    </TabsTrigger>
                    <TabsTrigger value="1h" className="text-xs px-2.5 py-1 font-mono">
                      1h
                    </TabsTrigger>
                    <TabsTrigger value="6h" className="text-xs px-2.5 py-1 font-mono">
                      6h
                    </TabsTrigger>
                    <TabsTrigger value="24h" className="text-xs px-2.5 py-1 font-mono">
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
                        Bandwidth Used (<span className="font-mono">{period}</span>)
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
                        <Globe className="w-3.5 h-3.5" /> WAN (<span className="font-mono">{period}</span>)
                      </span>
                    </TableHead>
                    <TableHead className="text-right">
                      <span className="inline-flex items-center gap-1 text-blue-600 dark:text-blue-400">
                        <Network className="w-3.5 h-3.5" /> LAN (<span className="font-mono">{period}</span>)
                      </span>
                    </TableHead>
                    <TableHead className="text-right">
                      <span className="inline-flex items-center gap-1">
                        <HardDrive className="w-3.5 h-3.5" /> Total (<span className="font-mono">{period}</span>)
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
                    const status = device.status || (device.arp?.isValid ? 'active' : 'unreachable')
                    const isOnline = status === 'active' || status === 'static'

                    const activeTraffic = trafficScope === 'wan' ? device.wan : trafficScope === 'lan' ? device.lan : device.total
                    const activeDlRate = Number(activeTraffic?.downloadBytesPerSec || 0)
                    const activeUlRate = Number(activeTraffic?.uploadBytesPerSec || 0)
                    const activeDlPktsRate = Number(activeTraffic?.downloadPacketsPerSec || 0)
                    const activeUlPktsRate = Number(activeTraffic?.uploadPacketsPerSec || 0)
                    const activeDlBytes = Number(activeTraffic?.downloadBytes || 0)
                    const activeUlBytes = Number(activeTraffic?.uploadBytes || 0)

                    // Individual scope metrics
                    const totalDlBytes = Number(device.total?.downloadBytes || 0)
                    const totalUlBytes = Number(device.total?.uploadBytes || 0)
                    const totalDlRate = Number(device.total?.downloadBytesPerSec || 0)
                    const totalUlRate = Number(device.total?.uploadBytesPerSec || 0)

                    const wanDlBytes = Number(device.wan?.downloadBytes || 0)
                    const wanUlBytes = Number(device.wan?.uploadBytes || 0)
                    const wanDlRate = Number(device.wan?.downloadBytesPerSec || 0)
                    const wanUlRate = Number(device.wan?.uploadBytesPerSec || 0)

                    const lanDlBytes = Number(device.lan?.downloadBytes || 0)
                    const lanUlBytes = Number(device.lan?.uploadBytes || 0)
                    const lanDlRate = Number(device.lan?.downloadBytesPerSec || 0)
                    const lanUlRate = Number(device.lan?.uploadBytesPerSec || 0)

                    const { icon: RowIcon } = getDeviceCategory(device.hostname, device.vendor)

                    return (
                      <TableRow
                        key={`${device.ipAddr}-${idx}`}
                        onClick={() => navigate(`/devices/${encodeURIComponent(device.ipAddr)}`)}
                        className="cursor-pointer hover:bg-muted/40 transition-colors group"
                      >
                        <TableCell className="font-medium">
                          <div className="flex items-center gap-2.5">
                            <div className="p-1.5 rounded-md bg-muted/60 text-muted-foreground group-hover:text-primary group-hover:bg-primary/10 transition-colors shrink-0">
                              <RowIcon className="w-4 h-4" />
                            </div>
                            <div className="flex flex-col">
                              <span className="font-semibold text-foreground group-hover:text-primary transition-colors flex items-center gap-1.5">
                                {device.hostname && !device.hostname.startsWith('unknown:')
                                  ? device.hostname
                                  : 'Unknown Device'}
                              </span>
                              <div className="flex items-center gap-1.5 text-xs text-muted-foreground font-mono">
                                <span>{device.ipAddr}</span>
                                {device.vendor && (
                                  <>
                                    <span>•</span>
                                    <span className="text-[11px] text-muted-foreground/80 font-sans truncate max-w-[150px]">
                                      {device.vendor}
                                    </span>
                                  </>
                                )}
                              </div>
                            </div>
                          </div>
                        </TableCell>
                        <TableCell className="font-mono text-xs">{device.ipAddr}</TableCell>
                        <TableCell className="font-mono text-xs text-muted-foreground">{device.macAddr}</TableCell>
                        {trafficScope !== 'split' && (
                          <TableCell className="font-mono text-xs">
                            <Badge variant="outline">{device.interface || device.arp?.interface || 'lan'}</Badge>
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
                            {status === 'offline' && Number(device.lastSeenUnix) > 0 && (
                              <span className="text-[10px] text-muted-foreground font-mono">
                                {formatRelativeTime(Number(device.lastSeenUnix))}
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
                                    <span className="text-[10px] text-muted-foreground font-mono">
                                      ({formatPacketsRate(activeDlPktsRate)})
                                    </span>
                                  </span>
                                  <span className="text-sky-600 dark:text-sky-400 font-medium text-xs flex items-center gap-1">
                                    <ArrowUp className="w-3 h-3 text-sky-500" />
                                    {formatRate(activeUlRate)}
                                    <span className="text-[10px] text-muted-foreground font-mono">
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
                                {trafficScope === 'total' && (wanDlBytes + wanUlBytes > 0 || lanDlBytes + lanUlBytes > 0) && (
                                  <span className="text-[10px] text-muted-foreground/80 flex items-center gap-1 mt-0.5 font-mono">
                                    <span className="text-emerald-600 dark:text-emerald-400">WAN {formatBytes(wanDlBytes + wanUlBytes)}</span>
                                    <span>•</span>
                                    <span className="text-blue-600 dark:text-blue-400">LAN {formatBytes(lanDlBytes + lanUlBytes)}</span>
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
                                  ↓ {formatBytes(wanDlBytes)} ↑ {formatBytes(wanUlBytes)}
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
                                  ↓ {formatBytes(lanDlBytes)} ↑ {formatBytes(lanUlBytes)}
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
                                  ↓ {formatBytes(totalDlBytes)} ↑ {formatBytes(totalUlBytes)}
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
  )
}
