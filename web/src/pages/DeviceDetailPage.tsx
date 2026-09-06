import { useEffect, useState, useMemo } from 'react'
import { useParams, Link } from 'react-router-dom'
import {
  ArrowLeft,
  Laptop,
  Globe,
  Network,
  HardDrive,
  Clock,
  Activity,
  Shield,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import {
  formatBytes,
  formatRate,
  formatPacketsRate,
  formatRelativeTime,
} from '@/lib/format'
import { rpcClient } from '@/lib/client'
import { useRootOutletContext } from '@/components/RootLayout'
import type { Device, DirectionalTraffic } from '@/gen/routermonitor/v1/router_monitor_pb'
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
} from 'recharts'
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from '@/components/ui/chart'

const deviceChartConfig = {
  download: {
    label: 'Download',
    color: '#10b981',
  },
  upload: {
    label: 'Upload',
    color: '#0ea5e9',
  },
} satisfies ChartConfig

export function DeviceDetailPage() {
  const { ip } = useParams<{ ip: string }>()
  const { devices, isRefreshing } = useRootOutletContext()

  const [timeRange, setTimeRange] = useState<'15m' | '1h' | '6h' | '24h'>('1h')
  const [loading, setLoading] = useState(false)
  const [historyData, setHistoryData] = useState<{ time: string; download: number; upload: number }[]>([])
  const [fetchedDevice, setFetchedDevice] = useState<Device | null>(null)
  const [updatedTraffic, setUpdatedTraffic] = useState<{
    total?: DirectionalTraffic
    wan?: DirectionalTraffic
    lan?: DirectionalTraffic
  } | null>(null)

  // Look up device from root context first
  const contextDevice = useMemo(() => {
    if (!ip) return null
    return devices.find((d) => d.ipAddr === ip) || null
  }, [devices, ip])

  const device = fetchedDevice || contextDevice

  useEffect(() => {
    if (!ip) return

    let active = true

    async function fetchDeviceHistory() {
      setLoading(true)
      try {
        const now = Math.floor(Date.now() / 1000)
        let from = now - 3600
        let step = 15
        if (timeRange === '15m') {
          from = now - 900
          step = 5
        } else if (timeRange === '6h') {
          from = now - 21600
          step = 60
        } else if (timeRange === '24h') {
          from = now - 86400
          step = 300
        }

        const [dlRes, ulRes, devRes] = await Promise.all([
          rpcClient.queryTimeSeries({
            metricName: 'device_traffic_bytes_rate',
            matchLabels: { ip: ip!, direction: 'ingress' },
            fromUnix: BigInt(from),
            toUnix: BigInt(now),
            stepSeconds: step,
          }),
          rpcClient.queryTimeSeries({
            metricName: 'device_traffic_bytes_rate',
            matchLabels: { ip: ip!, direction: 'egress' },
            fromUnix: BigInt(from),
            toUnix: BigInt(now),
            stepSeconds: step,
          }),
          rpcClient.listDevices({
            fromUnix: BigInt(from),
            toUnix: BigInt(now),
          }),
        ])

        if (!active) return

        const updated = devRes.devices.find((d) => d.ipAddr === ip)
        if (updated) {
          setFetchedDevice(updated)
          setUpdatedTraffic({
            total: updated.total,
            wan: updated.wan,
            lan: updated.lan,
          })
        }

        const dlPoints = dlRes.series[0]?.points || []
        const ulPoints = ulRes.series[0]?.points || []

        const mergedMap = new Map<number, { time: string; download: number; upload: number }>()

        for (const p of dlPoints) {
          const ts = Number(p.timestampUnix)
          const d = new Date(ts * 1000)
          const timeStr = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
          mergedMap.set(ts, { time: timeStr, download: p.value, upload: 0 })
        }

        for (const p of ulPoints) {
          const ts = Number(p.timestampUnix)
          const entry = mergedMap.get(ts)
          if (entry) {
            entry.upload = p.value
          } else {
            const d = new Date(ts * 1000)
            const timeStr = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
            mergedMap.set(ts, { time: timeStr, download: 0, upload: p.value })
          }
        }

        const sorted = Array.from(mergedMap.entries())
          .sort(([a], [b]) => a - b)
          .map(([_, v]) => v)

        setHistoryData(sorted)
      } catch (err) {
        console.error('Failed to load device history:', err)
      } finally {
        if (active) setLoading(false)
      }
    }

    fetchDeviceHistory()

    return () => {
      active = false
    }
  }, [ip, timeRange])

  if (!device && !loading && !isRefreshing) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Link to="/devices" className="flex items-center gap-1.5 hover:text-foreground transition-colors font-medium">
            <ArrowLeft className="w-4 h-4" /> Back to Devices
          </Link>
        </div>
        <Card className="text-center py-12 border-dashed">
          <CardContent className="space-y-4">
            <div className="mx-auto w-12 h-12 rounded-full bg-muted flex items-center justify-center text-muted-foreground">
              <Laptop className="w-6 h-6" />
            </div>
            <div>
              <h3 className="text-lg font-semibold">Device Not Found</h3>
              <p className="text-sm text-muted-foreground mt-1">
                No recorded device with IP address <span className="font-mono text-foreground">{ip}</span> was found.
              </p>
            </div>
            <Button asChild variant="outline" size="sm">
              <Link to="/devices">View All Devices</Link>
            </Button>
          </CardContent>
        </Card>
      </div>
    )
  }

  const status = device?.status || (device?.arp?.isValid ? 'active' : 'unreachable')
  const isOnline = status === 'active' || status === 'static'

  const totalTraffic = updatedTraffic?.total || device?.total
  const wanTraffic = updatedTraffic?.wan || device?.wan
  const lanTraffic = updatedTraffic?.lan || device?.lan

  const dlRate = Number(totalTraffic?.downloadBytesPerSec || 0)
  const ulRate = Number(totalTraffic?.uploadBytesPerSec || 0)
  const dlPktsRate = Number(totalTraffic?.downloadPacketsPerSec || 0)
  const ulPktsRate = Number(totalTraffic?.uploadPacketsPerSec || 0)

  const wanDlRate = Number(wanTraffic?.downloadBytesPerSec || 0)
  const wanUlRate = Number(wanTraffic?.uploadBytesPerSec || 0)
  const wanDlPktsRate = Number(wanTraffic?.downloadPacketsPerSec || 0)
  const wanUlPktsRate = Number(wanTraffic?.uploadPacketsPerSec || 0)

  const lanDlRate = Number(lanTraffic?.downloadBytesPerSec || 0)
  const lanUlRate = Number(lanTraffic?.uploadBytesPerSec || 0)
  const lanDlPktsRate = Number(lanTraffic?.downloadPacketsPerSec || 0)
  const lanUlPktsRate = Number(lanTraffic?.uploadPacketsPerSec || 0)

  const internetDl = Number(wanTraffic?.downloadBytes || 0)
  const internetUl = Number(wanTraffic?.uploadBytes || 0)
  const lanDl = Number(lanTraffic?.downloadBytes || 0)
  const lanUl = Number(lanTraffic?.uploadBytes || 0)

  const totalDl = Number(totalTraffic?.downloadBytes || (internetDl + lanDl))
  const totalUl = Number(totalTraffic?.uploadBytes || (internetUl + lanUl))

  return (
    <div className="space-y-6">
      {/* Breadcrumb & Navigation */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Link
            to="/devices"
            className="flex items-center gap-1.5 hover:text-foreground transition-colors font-medium text-xs sm:text-sm"
          >
            <ArrowLeft className="w-4 h-4" /> Devices
          </Link>
          <span>/</span>
          <span className="font-mono text-foreground font-semibold text-xs sm:text-sm">{ip}</span>
        </div>

        {/* Live Throughput Badge if online */}
        {isOnline && (dlRate > 0 || ulRate > 0) && (
          <div className="flex flex-wrap items-center gap-2">
            {(wanDlRate > 0 || wanUlRate > 0) && (
              <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-muted/60 text-xs font-mono">
                <Globe className="w-3.5 h-3.5 text-primary" />
                <span className="text-muted-foreground text-[10px]">WAN:</span>
                <span className="text-emerald-500 font-semibold">↓ {formatRate(wanDlRate)}</span>
                <span className="text-sky-500 font-semibold">↑ {formatRate(wanUlRate)}</span>
              </div>
            )}
            {(lanDlRate > 0 || lanUlRate > 0) && (
              <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-muted/60 text-xs font-mono">
                <Network className="w-3.5 h-3.5 text-sky-500" />
                <span className="text-muted-foreground text-[10px]">LAN:</span>
                <span className="text-emerald-500 font-semibold">↓ {formatRate(lanDlRate)}</span>
                <span className="text-sky-500 font-semibold">↑ {formatRate(lanUlRate)}</span>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Main Device Identity Card */}
      <Card>
        <CardHeader className="space-y-3 pb-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-start sm:items-center gap-3">
              <div className="p-3 rounded-lg bg-primary/10 text-primary shrink-0">
                <Laptop className="w-6 h-6" />
              </div>
              <div>
                <div className="flex flex-wrap items-center gap-2">
                  <h2 className="text-xl font-bold tracking-tight">
                    {device?.hostname && !device.hostname.startsWith('unknown:')
                      ? device.hostname
                      : 'Unknown Device'}
                  </h2>
                  <Badge
                    variant={isOnline ? 'outline' : 'secondary'}
                    className={cn(
                      'text-xs capitalize',
                      status === 'active' && 'border-emerald-500/20 bg-emerald-500/15 text-emerald-600 dark:text-emerald-400',
                      status === 'static' && 'border-sky-500/20 bg-sky-500/15 text-sky-600 dark:text-sky-400',
                      status === 'unreachable' && 'border-amber-500/20 bg-amber-500/15 text-amber-600 dark:text-amber-400',
                      status === 'offline' && 'border-muted bg-muted text-muted-foreground'
                    )}
                  >
                    {status === 'unreachable' ? 'Unreachable' : status}
                  </Badge>
                </div>
                <CardDescription className="font-mono text-xs flex flex-wrap items-center gap-x-4 gap-y-1 mt-1">
                  <span>IP: <strong className="text-foreground">{device?.ipAddr || ip}</strong></span>
                  <span>MAC: <strong className="text-foreground">{device?.macAddr || 'Unknown'}</strong></span>
                  <span>Interface: <strong className="text-foreground">{device?.interface || device?.arp?.interface || 'lan'}</strong></span>
                  {device?.arp && (
                    <span>ARP Flags: <strong className="text-foreground">0x{Number(device.arp.flags).toString(16)}</strong></span>
                  )}
                  {Number(device?.lastSeenUnix) > 0 && (
                    <span>Last seen: <strong className="text-foreground">{formatRelativeTime(Number(device?.lastSeenUnix))}</strong></span>
                  )}
                </CardDescription>
              </div>
            </div>
          </div>
        </CardHeader>
      </Card>

      {/* Traffic Breakdown Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Internet Traffic */}
        <Card className="bg-card">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center justify-between text-muted-foreground">
              <span className="flex items-center gap-1.5">
                <Globe className="w-4 h-4 text-primary" />
                Internet Traffic ({timeRange})
              </span>
              {(wanDlRate > 0 || wanUlRate > 0) && (
                <Badge variant="outline" className="text-[10px] px-1.5 py-0 border-primary/30 text-primary font-mono">
                  Live: {formatRate(wanDlRate + wanUlRate)}
                </Badge>
              )}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-2 gap-2 text-xs font-mono pt-1">
              <div>
                <span className="text-muted-foreground text-[11px] block">Download</span>
                <span className="font-semibold text-emerald-500 text-base">{formatBytes(internetDl)}</span>
                <span className="text-[10px] text-muted-foreground block">
                  Live: {formatRate(wanDlRate)} ({formatPacketsRate(wanDlPktsRate)})
                </span>
              </div>
              <div>
                <span className="text-muted-foreground text-[11px] block">Upload</span>
                <span className="font-semibold text-sky-500 text-base">{formatBytes(internetUl)}</span>
                <span className="text-[10px] text-muted-foreground block">
                  Live: {formatRate(wanUlRate)} ({formatPacketsRate(wanUlPktsRate)})
                </span>
              </div>
            </div>
            <div className="text-[11px] text-muted-foreground pt-2 border-t flex justify-between">
              <span>Total WAN ({timeRange}):</span>
              <strong className="text-foreground font-mono">{formatBytes(internetDl + internetUl)}</strong>
            </div>
          </CardContent>
        </Card>

        {/* Local LAN Traffic */}
        <Card className="bg-card">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center justify-between text-muted-foreground">
              <span className="flex items-center gap-1.5">
                <Network className="w-4 h-4 text-sky-500" />
                Local Traffic ({timeRange})
              </span>
              {(lanDlRate > 0 || lanUlRate > 0) && (
                <Badge variant="outline" className="text-[10px] px-1.5 py-0 border-sky-500/30 text-sky-500 font-mono">
                  Live: {formatRate(lanDlRate + lanUlRate)}
                </Badge>
              )}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-2 gap-2 text-xs font-mono pt-1">
              <div>
                <span className="text-muted-foreground text-[11px] block">Download</span>
                <span className="font-semibold text-emerald-500 text-base">{formatBytes(lanDl)}</span>
                <span className="text-[10px] text-muted-foreground block">
                  Live: {formatRate(lanDlRate)} ({formatPacketsRate(lanDlPktsRate)})
                </span>
              </div>
              <div>
                <span className="text-muted-foreground text-[11px] block">Upload</span>
                <span className="font-semibold text-sky-500 text-base">{formatBytes(lanUl)}</span>
                <span className="text-[10px] text-muted-foreground block">
                  Live: {formatRate(lanUlRate)} ({formatPacketsRate(lanUlPktsRate)})
                </span>
              </div>
            </div>
            <div className="text-[11px] text-muted-foreground pt-2 border-t flex justify-between">
              <span>Total LAN ({timeRange}):</span>
              <strong className="text-foreground font-mono">{formatBytes(lanDl + lanUl)}</strong>
            </div>
          </CardContent>
        </Card>

        {/* Total & Timestamps */}
        <Card className="bg-card">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center justify-between text-muted-foreground">
              <span className="flex items-center gap-1.5">
                <HardDrive className="w-4 h-4 text-muted-foreground" />
                Total Combined Traffic ({timeRange})
              </span>
              {(dlRate > 0 || ulRate > 0) && (
                <Badge variant="outline" className="text-[10px] px-1.5 py-0 border-emerald-500/30 text-emerald-600 dark:text-emerald-400 font-mono">
                  Live: {formatRate(dlRate + ulRate)}
                </Badge>
              )}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-2 gap-2 text-xs font-mono pt-1">
              <div>
                <span className="text-muted-foreground text-[11px] block">Total In</span>
                <span className="font-semibold text-emerald-500 text-base">{formatBytes(totalDl)}</span>
                <span className="text-[10px] text-muted-foreground block">
                  Live: {formatRate(dlRate)} ({formatPacketsRate(dlPktsRate)})
                </span>
              </div>
              <div>
                <span className="text-muted-foreground text-[11px] block">Total Out</span>
                <span className="font-semibold text-sky-500 text-base">{formatBytes(totalUl)}</span>
                <span className="text-[10px] text-muted-foreground block">
                  Live: {formatRate(ulRate)} ({formatPacketsRate(ulPktsRate)})
                </span>
              </div>
            </div>
            <div className="text-[11px] text-muted-foreground pt-2 border-t flex items-center justify-between">
              <span>Overall Total:</span>
              <strong className="text-foreground font-mono">{formatBytes(totalDl + totalUl)}</strong>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Historical Bandwidth Chart */}
      <Card>
        <CardHeader className="space-y-2 pb-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <CardTitle className="text-base flex items-center gap-2">
                <Clock className="w-4 h-4 text-primary" />
                Bandwidth History & Activity
              </CardTitle>
              <CardDescription>
                Historical ingress and egress data sampled from embedded SQLite TSDB
              </CardDescription>
            </div>
            <div className="flex items-center gap-1.5">
              {loading && <span className="text-xs text-muted-foreground animate-pulse mr-2">Querying TSDB...</span>}
              <div className="flex items-center gap-1 bg-muted/60 p-0.5 rounded-lg">
                {(['15m', '1h', '6h', '24h'] as const).map((r) => (
                  <Button
                    key={r}
                    variant={timeRange === r ? 'secondary' : 'ghost'}
                    size="sm"
                    className="h-7 text-xs px-2.5 font-mono"
                    onClick={() => setTimeRange(r)}
                  >
                    {r}
                  </Button>
                ))}
              </div>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="rounded-lg border bg-card p-4">
            {historyData.length === 0 ? (
              <div className="h-64 flex flex-col items-center justify-center text-muted-foreground text-xs text-center px-4">
                <Activity className="w-8 h-8 opacity-25 mb-2" />
                <span>No historical time series samples recorded for this device in the last {timeRange}.</span>
                <span className="text-[11px] opacity-75 mt-1">Data begins recording as soon as the device transmits network traffic.</span>
              </div>
            ) : (
              <ChartContainer config={deviceChartConfig} className="h-64 w-full">
                <AreaChart data={historyData} margin={{ top: 10, right: 10, left: -10, bottom: 0 }}>
                  <defs>
                    <linearGradient id="dev-detail-dl-grad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#10b981" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#10b981" stopOpacity={0.0} />
                    </linearGradient>
                    <linearGradient id="dev-detail-ul-grad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#0ea5e9" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#0ea5e9" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" vertical={false} className="stroke-muted/40" />
                  <XAxis dataKey="time" tickLine={false} axisLine={false} tickMargin={8} minTickGap={32} className="text-[10px] font-mono" />
                  <YAxis tickLine={false} axisLine={false} tickFormatter={(val) => formatRate(val)} className="text-[10px] font-mono" />
                  <ChartTooltip content={<ChartTooltipContent formatter={(val) => <span className="font-mono">{formatRate(Number(val))}</span>} />} />
                  <Area
                    type="monotone"
                    dataKey="download"
                    name="Download"
                    stroke="#10b981"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#dev-detail-dl-grad)"
                  />
                  <Area
                    type="monotone"
                    dataKey="upload"
                    name="Upload"
                    stroke="#0ea5e9"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#dev-detail-ul-grad)"
                  />
                </AreaChart>
              </ChartContainer>
            )}
          </div>
        </CardContent>
      </Card>

      {/* ARP & Network Diagnostics Card */}
      {device?.arp && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Shield className="w-4 h-4 text-primary" />
              ARP & Layer 2 Discovery Details
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs">
              <div>
                <span className="text-muted-foreground block text-[11px]">Hardware Type</span>
                <span className="font-mono font-medium">Ethernet (0x{Number(device.arp.hwType).toString(16)})</span>
              </div>
              <div>
                <span className="text-muted-foreground block text-[11px]">ARP Device Interface</span>
                <span className="font-mono font-medium">{device.arp.interface || 'lan'}</span>
              </div>
              <div>
                <span className="text-muted-foreground block text-[11px]">ARP Table State</span>
                <span className="font-mono font-medium">{device.arp.isValid ? 'Valid (Resolved)' : 'Incomplete / Unresolved'}</span>
              </div>
              <div>
                <span className="text-muted-foreground block text-[11px]">Kernel Flags</span>
                <span className="font-mono font-medium">0x{Number(device.arp.flags).toString(16)}</span>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
