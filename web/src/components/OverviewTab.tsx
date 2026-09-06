import { useEffect, useState, useMemo, useCallback } from 'react'
import { Link } from 'react-router-dom'
import {
  Globe,
  Laptop,
  Clock,
  ArrowDown,
  ArrowUp,
  Activity,
  Network,
  Columns2,
  HardDrive,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from './ui/card'
import { Badge } from './ui/badge'
import { Button } from './ui/button'
import { formatBytes, formatRate, formatLatency, formatPercent } from '@/lib/format'
import { rpcClient } from '@/lib/client'
import { cn } from '@/lib/utils'
import { useRootOutletContext } from './RootLayout'
import { getPeriodRange } from '@/lib/period'
import { getDeviceCategory } from '@/lib/device-icons'
import type { Device } from '@/gen/routermonitor/v1/router_monitor_pb'
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
} from 'recharts'
import { DEVICE_PALETTE } from './DeviceTrafficCharts'
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  ChartLegend,
  ChartLegendContent,
  type ChartConfig,
} from './ui/chart'

const wanChartConfig = {
  download: {
    label: 'WAN Download',
    color: '#10b981',
  },
  upload: {
    label: 'WAN Upload',
    color: '#0ea5e9',
  },
} satisfies ChartConfig

const lanChartConfig = {
  download: {
    label: 'LAN Ingress',
    color: '#3b82f6',
  },
  upload: {
    label: 'LAN Egress',
    color: '#8b5cf6',
  },
} satisfies ChartConfig

const totalChartConfig = {
  download: {
    label: 'Total Download',
    color: '#10b981',
  },
  upload: {
    label: 'Total Upload',
    color: '#0ea5e9',
  },
} satisfies ChartConfig

type ChartScope = 'wan' | 'lan' | 'total' | 'split'

interface OverviewTabProps {
  overview?: any
  devices?: any[]
  health?: any
}

interface TimeSeriesEntry {
  time: string
  download: number
  upload: number
}

function processSeriesPoints(dlPoints: any[], ulPoints: any[]): TimeSeriesEntry[] {
  const mergedMap = new Map<number, TimeSeriesEntry>()

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

  return Array.from(mergedMap.entries())
    .sort(([a], [b]) => a - b)
    .map(([_, v]) => v)
}

export function OverviewTab({
  overview: propOverview,
  devices: propDevices,
  health: propHealth,
}: OverviewTabProps) {
  const context = useRootOutletContext()
  const overview = propOverview || context?.overview
  const devices = (propDevices || context?.devices || []) as Device[]
  const health = propHealth || context?.health
  const period = context?.period || '24h'

  const [chartScope, setChartScope] = useState<ChartScope>('wan')
  const [historyLoading, setHistoryLoading] = useState(false)

  const [wanHistory, setWanHistory] = useState<TimeSeriesEntry[]>([])
  const [lanHistory, setLanHistory] = useState<TimeSeriesEntry[]>([])
  const [totalHistory, setTotalHistory] = useState<TimeSeriesEntry[]>([])

  const fetchHistory = useCallback(async () => {
    setHistoryLoading(true)
    try {
      const { fromUnix: from, toUnix: now, stepSeconds: step } = getPeriodRange(period)

      if (chartScope === 'wan' || chartScope === 'split') {
        const [dlRes, ulRes] = await Promise.all([
          rpcClient.queryTimeSeries({
            metricName: 'wan_traffic_bytes_rate',
            matchLabels: { direction: 'ingress' },
            fromUnix: BigInt(from),
            toUnix: BigInt(now),
            stepSeconds: step,
          }),
          rpcClient.queryTimeSeries({
            metricName: 'wan_traffic_bytes_rate',
            matchLabels: { direction: 'egress' },
            fromUnix: BigInt(from),
            toUnix: BigInt(now),
            stepSeconds: step,
          }),
        ])
        setWanHistory(processSeriesPoints(dlRes.series[0]?.points || [], ulRes.series[0]?.points || []))
      }

      if (chartScope === 'lan' || chartScope === 'split') {
        const [dlRes, ulRes] = await Promise.all([
          rpcClient.queryTimeSeries({
            metricName: 'lan_traffic_bytes_rate',
            matchLabels: { direction: 'ingress' },
            fromUnix: BigInt(from),
            toUnix: BigInt(now),
            stepSeconds: step,
          }),
          rpcClient.queryTimeSeries({
            metricName: 'lan_traffic_bytes_rate',
            matchLabels: { direction: 'egress' },
            fromUnix: BigInt(from),
            toUnix: BigInt(now),
            stepSeconds: step,
          }),
        ])
        setLanHistory(processSeriesPoints(dlRes.series[0]?.points || [], ulRes.series[0]?.points || []))
      }

      if (chartScope === 'total') {
        const [dlRes, ulRes] = await Promise.all([
          rpcClient.queryTimeSeries({
            metricName: 'traffic_bytes_rate',
            matchLabels: { direction: 'ingress' },
            fromUnix: BigInt(from),
            toUnix: BigInt(now),
            stepSeconds: step,
          }),
          rpcClient.queryTimeSeries({
            metricName: 'traffic_bytes_rate',
            matchLabels: { direction: 'egress' },
            fromUnix: BigInt(from),
            toUnix: BigInt(now),
            stepSeconds: step,
          }),
        ])
        setTotalHistory(processSeriesPoints(dlRes.series[0]?.points || [], ulRes.series[0]?.points || []))
      }
    } catch (err) {
      console.error('Failed to load history from SQLite TSDB:', err)
    } finally {
      setHistoryLoading(false)
    }
  }, [period, chartScope])

  useEffect(() => {
    fetchHistory()
    const interval = setInterval(fetchHistory, 15000)
    return () => clearInterval(interval)
  }, [fetchHistory])

  const topWanDevices = useMemo(() => {
    if (!devices || devices.length === 0) return []
    return [...devices]
      .map((d) => {
        const dl = Number(d.wan?.downloadBytes || 0)
        const ul = Number(d.wan?.uploadBytes || 0)
        const liveDl = Number(d.wan?.downloadBytesPerSec || 0)
        const liveUl = Number(d.wan?.uploadBytesPerSec || 0)
        return { device: d, dl, ul, total: dl + ul, liveDl, liveUl }
      })
      .filter((x) => x.total > 0 || x.device.status === 'active' || x.device.status === 'static')
      .sort((a, b) => b.total - a.total)
      .slice(0, 5)
  }, [devices])

  const topLanDevices = useMemo(() => {
    if (!devices || devices.length === 0) return []
    return [...devices]
      .map((d) => {
        const dl = Number(d.lan?.downloadBytes || 0)
        const ul = Number(d.lan?.uploadBytes || 0)
        const liveDl = Number(d.lan?.downloadBytesPerSec || 0)
        const liveUl = Number(d.lan?.uploadBytesPerSec || 0)
        return { device: d, dl, ul, total: dl + ul, liveDl, liveUl }
      })
      .filter((x) => x.total > 0 || x.device.status === 'active' || x.device.status === 'static')
      .sort((a, b) => b.total - a.total)
      .slice(0, 5)
  }, [devices])

  const wanPieData = useMemo(() => {
    if (!topWanDevices || topWanDevices.length === 0) return []
    const sum = topWanDevices.reduce((acc, d) => acc + d.total, 0)
    if (sum === 0) return []
    return topWanDevices.map((d, index) => ({
      name: d.device.hostname && !d.device.hostname.startsWith('unknown:') ? d.device.hostname : (d.device.vendor || d.device.ipAddr),
      ip: d.device.ipAddr,
      value: d.total,
      color: DEVICE_PALETTE[index % DEVICE_PALETTE.length],
    }))
  }, [topWanDevices])

  const lanPieData = useMemo(() => {
    if (!topLanDevices || topLanDevices.length === 0) return []
    const sum = topLanDevices.reduce((acc, d) => acc + d.total, 0)
    if (sum === 0) return []
    return topLanDevices.map((d, index) => ({
      name: d.device.hostname && !d.device.hostname.startsWith('unknown:') ? d.device.hostname : (d.device.vendor || d.device.ipAddr),
      ip: d.device.ipAddr,
      value: d.total,
      color: DEVICE_PALETTE[index % DEVICE_PALETTE.length],
    }))
  }, [topLanDevices])

  const scopeRates = useMemo(() => {
    if (chartScope === 'wan') {
      return {
        label: 'Internet (WAN)',
        downRate: overview?.wan?.downloadBytesPerSec,
        upRate: overview?.wan?.uploadBytesPerSec,
        downVol: overview?.wan?.downloadBytes,
        upVol: overview?.wan?.uploadBytes,
      }
    }
    if (chartScope === 'lan') {
      return {
        label: 'Local Network (LAN)',
        downRate: overview?.lan?.downloadBytesPerSec,
        upRate: overview?.lan?.uploadBytesPerSec,
        downVol: overview?.lan?.downloadBytes,
        upVol: overview?.lan?.uploadBytes,
      }
    }
    return {
      label: 'Combined Network (Total)',
      downRate: overview?.total?.downloadBytesPerSec,
      upRate: overview?.total?.uploadBytesPerSec,
      downVol: overview?.total?.downloadBytes,
      upVol: overview?.total?.uploadBytes,
    }
  }, [chartScope, overview])

  return (
    <div className="space-y-6">
      {/* 1. Top KPI Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* WAN Traffic Card */}
        <Card
          className={cn(
            "transition-all cursor-pointer hover:border-emerald-500/50 relative overflow-hidden",
            chartScope === 'wan' && "ring-2 ring-emerald-500/30 border-emerald-500/40 bg-emerald-500/[0.02]"
          )}
          onClick={() => setChartScope('wan')}
        >
          <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded-md bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
                <Globe className="h-4 w-4" />
              </div>
              <CardTitle className="text-sm font-semibold">Internet (WAN)</CardTitle>
            </div>
            <Badge variant="outline" className="text-[10px] border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 font-mono">
              External
            </Badge>
          </CardHeader>
          <CardContent className="space-y-2.5">
            <div className="grid grid-cols-2 gap-2 pt-1">
              <div>
                <span className="text-[11px] text-muted-foreground flex items-center gap-1 font-medium">
                  <ArrowDown className="w-3 h-3 text-emerald-500" /> Down
                </span>
                <div className="text-lg font-bold font-mono text-emerald-600 dark:text-emerald-400">
                  {formatRate(overview?.wan?.downloadBytesPerSec)}
                </div>
                <div className="text-[10px] text-muted-foreground mt-0.5">
                  Total: <span className="font-mono font-medium text-foreground">{formatBytes(overview?.wan?.downloadBytes)}</span>
                </div>
              </div>
              <div>
                <span className="text-[11px] text-muted-foreground flex items-center gap-1 font-medium">
                  <ArrowUp className="w-3 h-3 text-sky-500" /> Up
                </span>
                <div className="text-lg font-bold font-mono text-sky-600 dark:text-sky-400">
                  {formatRate(overview?.wan?.uploadBytesPerSec)}
                </div>
                <div className="text-[10px] text-muted-foreground mt-0.5">
                  Total: <span className="font-mono font-medium text-foreground">{formatBytes(overview?.wan?.uploadBytes)}</span>
                </div>
              </div>
            </div>
            <div className="pt-2 border-t flex items-center justify-between text-xs">
              <span className="text-muted-foreground">Combined ({period}):</span>
              <span className="font-mono font-semibold text-foreground">
                {formatBytes(Number(overview?.wan?.downloadBytes || 0) + Number(overview?.wan?.uploadBytes || 0))}
              </span>
            </div>
          </CardContent>
        </Card>

        {/* LAN Traffic Card */}
        <Card
          className={cn(
            "transition-all cursor-pointer hover:border-blue-500/50 relative overflow-hidden",
            chartScope === 'lan' && "ring-2 ring-blue-500/30 border-blue-500/40 bg-blue-500/[0.02]"
          )}
          onClick={() => setChartScope('lan')}
        >
          <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded-md bg-blue-500/10 text-blue-600 dark:text-blue-400">
                <Network className="h-4 w-4" />
              </div>
              <CardTitle className="text-sm font-semibold">Local (LAN)</CardTitle>
            </div>
            <Badge variant="outline" className="text-[10px] border-blue-500/30 bg-blue-500/10 text-blue-600 dark:text-blue-400 font-mono">
              Internal
            </Badge>
          </CardHeader>
          <CardContent className="space-y-2.5">
            <div className="grid grid-cols-2 gap-2 pt-1">
              <div>
                <span className="text-[11px] text-muted-foreground flex items-center gap-1 font-medium">
                  <ArrowDown className="w-3 h-3 text-blue-500" /> Ingress
                </span>
                <div className="text-lg font-bold font-mono text-blue-600 dark:text-blue-400">
                  {formatRate(overview?.lan?.downloadBytesPerSec)}
                </div>
                <div className="text-[10px] text-muted-foreground mt-0.5">
                  Total: <span className="font-mono font-medium text-foreground">{formatBytes(overview?.lan?.downloadBytes)}</span>
                </div>
              </div>
              <div>
                <span className="text-[11px] text-muted-foreground flex items-center gap-1 font-medium">
                  <ArrowUp className="w-3 h-3 text-indigo-500" /> Egress
                </span>
                <div className="text-lg font-bold font-mono text-indigo-600 dark:text-indigo-400">
                  {formatRate(overview?.lan?.uploadBytesPerSec)}
                </div>
                <div className="text-[10px] text-muted-foreground mt-0.5">
                  Total: <span className="font-mono font-medium text-foreground">{formatBytes(overview?.lan?.uploadBytes)}</span>
                </div>
              </div>
            </div>
            <div className="pt-2 border-t flex items-center justify-between text-xs">
              <span className="text-muted-foreground">Combined ({period}):</span>
              <span className="font-mono font-semibold text-foreground">
                {formatBytes(Number(overview?.lan?.downloadBytes || 0) + Number(overview?.lan?.uploadBytes || 0))}
              </span>
            </div>
          </CardContent>
        </Card>

        {/* Internet Health Card */}
        <Link to="/health" className="block focus:outline-hidden group">
          <Card className="hover:border-primary/50 transition-all h-full">
            <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
              <div className="flex items-center gap-2">
                <div className="p-1.5 rounded-md bg-muted text-foreground">
                  <Activity className="h-4 w-4 text-primary" />
                </div>
                <CardTitle className="text-sm font-semibold">Internet Health</CardTitle>
              </div>
              <Badge
                variant={overview?.internetStatus === 'down' || !overview?.internetIsUp ? "destructive" : "outline"}
                className={cn(
                  "font-normal capitalize text-[10px]",
                  overview?.internetStatus === 'degraded' && "border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400",
                  (overview?.internetStatus === 'operational' || (!overview?.internetStatus && overview?.internetIsUp)) && "border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                )}
              >
                {overview?.internetStatus || (overview?.internetIsUp ? "Online" : "Offline")}
              </Badge>
            </CardHeader>
            <CardContent className="space-y-2.5">
              <div className="pt-1">
                <div className="text-lg font-bold font-mono tracking-tight text-foreground flex items-baseline gap-1.5">
                  {formatLatency(overview?.internetLatencySeconds)}
                  <span className="text-[11px] font-normal text-muted-foreground">RTT latency</span>
                </div>
              </div>
              <div className="pt-2 border-t flex items-center justify-between text-xs text-muted-foreground">
                <span>Loss: <span className="font-mono text-foreground font-medium">{formatPercent(overview?.internetPacketLossRatio)}</span></span>
                <span>Targets: <span className="font-mono text-foreground font-medium">{health?.targets ? `${health.targets.filter((t: any) => t.isUp).length}/${health.targets.length}` : (overview?.internetIsUp ? '1/1' : '0/1')} Up</span></span>
              </div>
            </CardContent>
          </Card>
        </Link>

        {/* Connected Devices Card */}
        <Link to="/devices" className="block focus:outline-hidden group">
          <Card className="hover:border-primary/50 transition-all h-full">
            <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
              <div className="flex items-center gap-2">
                <div className="p-1.5 rounded-md bg-muted text-foreground">
                  <Laptop className="h-4 w-4 text-primary" />
                </div>
                <CardTitle className="text-sm font-semibold">Devices</CardTitle>
              </div>
              <Badge variant="outline" className="font-mono text-[10px]">
                {overview?.interfaceName || 'lan'}
              </Badge>
            </CardHeader>
            <CardContent className="space-y-2.5">
              <div className="pt-1">
                <div className="text-lg font-bold font-mono tracking-tight text-foreground flex items-baseline gap-1.5">
                  {overview?.connectedDevicesCount || 0}
                  <span className="text-[11px] font-normal text-muted-foreground">active devices</span>
                </div>
              </div>
              <div className="pt-2 border-t flex items-center justify-between text-xs text-muted-foreground">
                <span>Subnet:</span>
                <span className="font-mono text-foreground font-medium">{overview?.lanSubnetCidr || '10.100.0.0/16'}</span>
              </div>
            </CardContent>
          </Card>
        </Link>
      </div>

      {/* 2. Bandwidth History & Activity Section with LAN/WAN Scope Toggles */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <CardTitle className="flex items-center gap-2 text-base">
                <Clock className="w-4 h-4 text-primary" />
                Network Bandwidth
              </CardTitle>
              <CardDescription className="text-xs">
                Time-series bandwidth telemetry recorded in embedded SQLite TSDB
              </CardDescription>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              {/* Scope Selector Button Group */}
              <div className="flex items-center gap-1 bg-muted/80 p-1 rounded-lg">
                <Button
                  variant={chartScope === 'wan' ? 'default' : 'ghost'}
                  size="sm"
                  className={cn(
                    "h-7 text-xs px-2.5 font-medium gap-1.5 transition-all",
                    chartScope === 'wan' && "bg-emerald-600 hover:bg-emerald-700 text-white shadow-xs"
                  )}
                  onClick={() => setChartScope('wan')}
                >
                  <Globe className="w-3.5 h-3.5" />
                  <span>Internet (WAN)</span>
                </Button>

                <Button
                  variant={chartScope === 'lan' ? 'default' : 'ghost'}
                  size="sm"
                  className={cn(
                    "h-7 text-xs px-2.5 font-medium gap-1.5 transition-all",
                    chartScope === 'lan' && "bg-blue-600 hover:bg-blue-700 text-white shadow-xs"
                  )}
                  onClick={() => setChartScope('lan')}
                >
                  <Network className="w-3.5 h-3.5" />
                  <span>Local (LAN)</span>
                </Button>

                <Button
                  variant={chartScope === 'total' ? 'default' : 'ghost'}
                  size="sm"
                  className="h-7 text-xs px-2.5 font-medium transition-all"
                  onClick={() => setChartScope('total')}
                >
                  <HardDrive className="w-3.5 h-3.5" />
                  <span>Combined (Total)</span>
                </Button>

                <Button
                  variant={chartScope === 'split' ? 'secondary' : 'ghost'}
                  size="sm"
                  className="h-7 text-xs px-2.5 font-medium gap-1 transition-all"
                  onClick={() => setChartScope('split')}
                >
                  <Columns2 className="w-3.5 h-3.5" />
                  <span>Split View</span>
                </Button>
              </div>

              <Badge variant="outline" className="font-mono text-xs px-2 py-0.5 ml-1">
                {period}
              </Badge>
            </div>
          </div>

          {/* Rate Readout for Single Scope Mode */}
          {chartScope !== 'split' && (
            <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 pt-2 border-t text-xs">
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                <span className="font-medium text-foreground">{scopeRates.label} Totals ({period}):</span>
                <span className="text-muted-foreground">
                  Down: <span className="font-mono font-medium text-foreground">{formatBytes(scopeRates.downVol)}</span>
                </span>
                <span className="text-muted-foreground">
                  Up: <span className="font-mono font-medium text-foreground">{formatBytes(scopeRates.upVol)}</span>
                </span>
                <span className="text-muted-foreground">
                  Combined: <span className="font-mono font-semibold text-foreground">{formatBytes(Number(scopeRates.downVol || 0) + Number(scopeRates.upVol || 0))}</span>
                </span>
              </div>
              <div className="flex items-center gap-3">
                <div className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 inline-block" />
                  <span className="text-muted-foreground">Live Down:</span>
                  <span className="font-mono font-semibold text-emerald-600 dark:text-emerald-400">
                    {formatRate(scopeRates.downRate)}
                  </span>
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-sky-500 inline-block" />
                  <span className="text-muted-foreground">Live Up:</span>
                  <span className="font-mono font-semibold text-sky-600 dark:text-sky-400">
                    {formatRate(scopeRates.upRate)}
                  </span>
                </div>
              </div>
            </div>
          )}
        </CardHeader>

        <CardContent className="pt-1">
          {/* Split View: Twin Side-by-Side Charts */}
          {chartScope === 'split' ? (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* WAN Sub-chart */}
              <div className="space-y-2 p-3 rounded-lg border bg-muted/20">
                <div className="flex items-center justify-between text-xs">
                  <div className="flex items-center gap-1.5 font-semibold text-emerald-600 dark:text-emerald-400">
                    <Globe className="w-3.5 h-3.5" />
                    <span>Internet (WAN) Throughput</span>
                  </div>
                  <div className="flex items-center gap-2 font-mono text-[11px]">
                    <span className="text-emerald-500">↓ {formatRate(overview?.wan?.downloadBytesPerSec)}</span>
                    <span className="text-sky-500">↑ {formatRate(overview?.wan?.uploadBytesPerSec)}</span>
                  </div>
                </div>
                <div className="h-[240px] w-full">
                  {wanHistory.length === 0 ? (
                    <div className="h-full flex items-center justify-center text-xs text-muted-foreground">
                      {historyLoading ? 'Loading WAN metrics...' : 'No WAN records in TSDB yet.'}
                    </div>
                  ) : (
                    <ChartContainer config={wanChartConfig} className="h-[240px] w-full aspect-auto">
                      <AreaChart data={wanHistory}>
                        <defs>
                          <linearGradient id="wanDlGrad" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#10b981" stopOpacity={0.4} />
                            <stop offset="95%" stopColor="#10b981" stopOpacity={0.0} />
                          </linearGradient>
                          <linearGradient id="wanUlGrad" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#0ea5e9" stopOpacity={0.4} />
                            <stop offset="95%" stopColor="#0ea5e9" stopOpacity={0.0} />
                          </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" vertical={false} />
                        <XAxis dataKey="time" tickLine={false} axisLine={false} tickMargin={8} fontSize={10} className="font-mono" />
                        <YAxis tickLine={false} axisLine={false} fontSize={10} tickFormatter={(val) => formatBytes(val)} width={65} className="font-mono" />
                        <ChartTooltip
                          content={
                            <ChartTooltipContent
                              formatter={(value, name, item) => (
                                <div className="flex items-center justify-between gap-2">
                                  <div className="h-2 w-2 rounded-full" style={{ backgroundColor: item.color }} />
                                  <span className="text-muted-foreground text-xs">{wanChartConfig[name as keyof typeof wanChartConfig]?.label ?? name}:</span>
                                  <span className="font-mono font-medium">{formatRate(Number(value))}</span>
                                </div>
                              )}
                            />
                          }
                        />
                        <Area type="monotone" dataKey="download" stroke="#10b981" strokeWidth={2} fillOpacity={1} fill="url(#wanDlGrad)" />
                        <Area type="monotone" dataKey="upload" stroke="#0ea5e9" strokeWidth={2} fillOpacity={1} fill="url(#wanUlGrad)" />
                      </AreaChart>
                    </ChartContainer>
                  )}
                </div>
                <div className="flex flex-wrap items-center justify-between gap-1 text-[11px] pt-1.5 border-t border-border/40 text-muted-foreground">
                  <span>Down Total: <span className="font-mono font-medium text-foreground">{formatBytes(overview?.wan?.downloadBytes)}</span></span>
                  <span>Up Total: <span className="font-mono font-medium text-foreground">{formatBytes(overview?.wan?.uploadBytes)}</span></span>
                  <span>Combined ({period}): <span className="font-mono font-semibold text-foreground">{formatBytes(Number(overview?.wan?.downloadBytes || 0) + Number(overview?.wan?.uploadBytes || 0))}</span></span>
                </div>
              </div>

              {/* LAN Sub-chart */}
              <div className="space-y-2 p-3 rounded-lg border bg-muted/20">
                <div className="flex items-center justify-between text-xs">
                  <div className="flex items-center gap-1.5 font-semibold text-blue-600 dark:text-blue-400">
                    <Network className="w-3.5 h-3.5" />
                    <span>Local Network (LAN) Throughput</span>
                  </div>
                  <div className="flex items-center gap-2 font-mono text-[11px]">
                    <span className="text-blue-500">↓ {formatRate(overview?.lan?.downloadBytesPerSec)}</span>
                    <span className="text-indigo-500">↑ {formatRate(overview?.lan?.uploadBytesPerSec)}</span>
                  </div>
                </div>
                <div className="h-[240px] w-full">
                  {lanHistory.length === 0 ? (
                    <div className="h-full flex items-center justify-center text-xs text-muted-foreground">
                      {historyLoading ? 'Loading LAN metrics...' : 'No LAN records in TSDB yet.'}
                    </div>
                  ) : (
                    <ChartContainer config={lanChartConfig} className="h-[240px] w-full aspect-auto">
                      <AreaChart data={lanHistory}>
                        <defs>
                          <linearGradient id="lanDlGrad" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.4} />
                            <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.0} />
                          </linearGradient>
                          <linearGradient id="lanUlGrad" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#8b5cf6" stopOpacity={0.4} />
                            <stop offset="95%" stopColor="#8b5cf6" stopOpacity={0.0} />
                          </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" vertical={false} />
                        <XAxis dataKey="time" tickLine={false} axisLine={false} tickMargin={8} fontSize={10} className="font-mono" />
                        <YAxis tickLine={false} axisLine={false} fontSize={10} tickFormatter={(val) => formatBytes(val)} width={65} className="font-mono" />
                        <ChartTooltip
                          content={
                            <ChartTooltipContent
                              formatter={(value, name, item) => (
                                <div className="flex items-center justify-between gap-2">
                                  <div className="h-2 w-2 rounded-full" style={{ backgroundColor: item.color }} />
                                  <span className="text-muted-foreground text-xs">{lanChartConfig[name as keyof typeof lanChartConfig]?.label ?? name}:</span>
                                  <span className="font-mono font-medium">{formatRate(Number(value))}</span>
                                </div>
                              )}
                            />
                          }
                        />
                        <Area type="monotone" dataKey="download" stroke="#3b82f6" strokeWidth={2} fillOpacity={1} fill="url(#lanDlGrad)" />
                        <Area type="monotone" dataKey="upload" stroke="#8b5cf6" strokeWidth={2} fillOpacity={1} fill="url(#lanUlGrad)" />
                      </AreaChart>
                    </ChartContainer>
                  )}
                </div>
                <div className="flex flex-wrap items-center justify-between gap-1 text-[11px] pt-1.5 border-t border-border/40 text-muted-foreground">
                  <span>Ingress Total: <span className="font-mono font-medium text-foreground">{formatBytes(overview?.lan?.downloadBytes)}</span></span>
                  <span>Egress Total: <span className="font-mono font-medium text-foreground">{formatBytes(overview?.lan?.uploadBytes)}</span></span>
                  <span>Combined ({period}): <span className="font-mono font-semibold text-foreground">{formatBytes(Number(overview?.lan?.downloadBytes || 0) + Number(overview?.lan?.uploadBytes || 0))}</span></span>
                </div>
              </div>
            </div>
          ) : (
            /* Single Full-width Chart */
            <div className="h-[300px] w-full">
              {historyLoading &&
              (chartScope === 'wan' ? wanHistory : chartScope === 'lan' ? lanHistory : totalHistory).length === 0 ? (
                <div className="h-full flex items-center justify-center text-sm text-muted-foreground">
                  Loading historical time series...
                </div>
              ) : (chartScope === 'wan' ? wanHistory : chartScope === 'lan' ? lanHistory : totalHistory).length === 0 ? (
                <div className="h-full flex flex-col items-center justify-center text-sm text-muted-foreground text-center px-4">
                  <span>No historical records in TSDB for {scopeRates.label} yet.</span>
                  <span className="text-xs opacity-75 mt-1">Metrics are sampled every 15 seconds.</span>
                </div>
              ) : (
                <ChartContainer
                  config={chartScope === 'lan' ? lanChartConfig : chartScope === 'wan' ? wanChartConfig : totalChartConfig}
                  className="h-[300px] w-full aspect-auto"
                >
                  <AreaChart
                    data={
                      chartScope === 'wan'
                        ? wanHistory
                        : chartScope === 'lan'
                        ? lanHistory
                        : totalHistory
                    }
                  >
                    <defs>
                      <linearGradient id="singleDlGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop
                          offset="5%"
                          stopColor={chartScope === 'lan' ? '#3b82f6' : '#10b981'}
                          stopOpacity={0.4}
                        />
                        <stop
                          offset="95%"
                          stopColor={chartScope === 'lan' ? '#3b82f6' : '#10b981'}
                          stopOpacity={0.0}
                        />
                      </linearGradient>
                      <linearGradient id="singleUlGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop
                          offset="5%"
                          stopColor={chartScope === 'lan' ? '#8b5cf6' : '#0ea5e9'}
                          stopOpacity={0.4}
                        />
                        <stop
                          offset="95%"
                          stopColor={chartScope === 'lan' ? '#8b5cf6' : '#0ea5e9'}
                          stopOpacity={0.0}
                        />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" vertical={false} />
                    <XAxis dataKey="time" tickLine={false} axisLine={false} tickMargin={8} fontSize={11} className="font-mono" />
                    <YAxis
                      tickLine={false}
                      axisLine={false}
                      fontSize={11}
                      tickFormatter={(val) => formatBytes(val)}
                      width={75}
                      className="font-mono"
                    />
                    <ChartTooltip
                      cursor={false}
                      content={
                        <ChartTooltipContent
                          indicator="dot"
                          formatter={(value, name, item) => (
                            <>
                              <div
                                className="h-2.5 w-2.5 shrink-0 rounded-[2px]"
                                style={{ backgroundColor: item.color }}
                              />
                              <div className="flex flex-1 justify-between items-center leading-none gap-2">
                                <span className="text-muted-foreground">
                                  {chartScope === 'lan'
                                    ? lanChartConfig[name as keyof typeof lanChartConfig]?.label ?? name
                                    : chartScope === 'wan'
                                    ? wanChartConfig[name as keyof typeof wanChartConfig]?.label ?? name
                                    : totalChartConfig[name as keyof typeof totalChartConfig]?.label ?? name}
                                </span>
                                <span className="font-mono font-medium text-foreground tabular-nums">
                                  {formatRate(Number(value))}
                                </span>
                              </div>
                            </>
                          )}
                        />
                      }
                    />
                    <Area
                      type="monotone"
                      dataKey="download"
                      stroke={chartScope === 'lan' ? '#3b82f6' : '#10b981'}
                      strokeWidth={2}
                      fillOpacity={1}
                      fill="url(#singleDlGrad)"
                    />
                    <Area
                      type="monotone"
                      dataKey="upload"
                      stroke={chartScope === 'lan' ? '#8b5cf6' : '#0ea5e9'}
                      strokeWidth={2}
                      fillOpacity={1}
                      fill="url(#singleUlGrad)"
                    />
                    <ChartLegend content={<ChartLegendContent className="text-xs pt-3" />} />
                  </AreaChart>
                </ChartContainer>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* 3. At-A-Glance Insights: Top WAN and LAN Consumers Separately */}
      {(topWanDevices.length > 0 || topLanDevices.length > 0) && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Top WAN Consumers Card */}
          <Card>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="p-1.5 rounded-md bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
                    <Globe className="w-4 h-4" />
                  </div>
                  <div>
                    <CardTitle className="text-sm font-semibold">Top Internet (WAN) Consumers</CardTitle>
                    <CardDescription className="text-xs">Highest external traffic volume ({period})</CardDescription>
                  </div>
                </div>
                <Badge variant="outline" className="text-[10px] border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 font-mono">
                  External
                </Badge>
              </div>
            </CardHeader>
            <CardContent>
              {topWanDevices.length === 0 ? (
                <div className="py-8 text-center text-xs text-muted-foreground">
                  No active WAN client traffic recorded for this period.
                </div>
              ) : (
                <div className="flex flex-col sm:flex-row items-center gap-5">
                  <div className="relative w-28 h-28 shrink-0 flex items-center justify-center">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={wanPieData}
                          dataKey="value"
                          nameKey="name"
                          innerRadius={28}
                          outerRadius={44}
                          paddingAngle={2}
                          stroke="transparent"
                        >
                          {wanPieData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} />
                          ))}
                        </Pie>
                      </PieChart>
                    </ResponsiveContainer>
                    <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none select-none text-center">
                      <span className="text-[9px] uppercase font-semibold text-muted-foreground">WAN</span>
                      <span className="text-xs font-bold font-mono text-foreground leading-none">
                        {formatBytes(Number(overview?.wan?.downloadBytes || 0) + Number(overview?.wan?.uploadBytes || 0))}
                      </span>
                    </div>
                  </div>

                  <div className="flex-1 w-full space-y-2 min-w-0">
                    {topWanDevices.map(({ device: d, dl, ul, total, liveDl, liveUl }, index) => {
                      const { icon: DevIcon } = getDeviceCategory(d.hostname, d.vendor)
                      const dName = d.hostname && !d.hostname.startsWith('unknown:') ? d.hostname : (d.vendor || d.ipAddr)
                      const liveRate = liveDl + liveUl
                      const color = DEVICE_PALETTE[index % DEVICE_PALETTE.length]

                      return (
                        <Link
                          key={d.ipAddr || index}
                          to={`/devices/${d.ipAddr}`}
                          className="flex items-center justify-between p-2 rounded-lg border bg-card/60 hover:bg-muted/40 hover:border-emerald-500/40 transition-all group text-xs"
                        >
                          <div className="flex items-center gap-2 min-w-0 pr-2">
                            <span
                              className="w-2 h-2 rounded-full shrink-0"
                              style={{ backgroundColor: color }}
                            />
                            <span className="text-xs font-mono font-semibold text-muted-foreground w-3.5 text-center shrink-0">
                              #{index + 1}
                            </span>
                            <div className="p-1 rounded-md bg-muted text-muted-foreground group-hover:text-emerald-600 dark:group-hover:text-emerald-400 transition-colors shrink-0">
                              <DevIcon className="w-3.5 h-3.5" />
                            </div>
                            <div className="min-w-0">
                              <div className="flex items-center gap-1.5">
                                <h4 className="text-xs font-semibold truncate text-foreground group-hover:text-emerald-600 dark:group-hover:text-emerald-400 transition-colors">
                                  {dName}
                                </h4>
                                {d.vendor && dName !== d.vendor && (
                                  <span className="text-[10px] text-muted-foreground truncate hidden sm:inline">
                                    ({d.vendor})
                                  </span>
                                )}
                              </div>
                              <span className="text-[10px] font-mono text-muted-foreground block truncate">
                                {d.ipAddr}
                              </span>
                            </div>
                          </div>

                          <div className="text-right shrink-0">
                            <div className="text-xs font-mono font-bold text-foreground">
                              {formatBytes(total)}
                            </div>
                            <div className="text-[10px] font-mono text-muted-foreground flex items-center justify-end gap-1.5">
                              <span className="text-emerald-600 dark:text-emerald-400">↓ {formatBytes(dl)}</span>
                              <span className="text-sky-600 dark:text-sky-400">↑ {formatBytes(ul)}</span>
                            </div>
                            {liveRate > 0 && (
                              <div className="text-[10px] font-mono text-primary flex items-center justify-end gap-1 pt-0.5">
                                <span>Live:</span>
                                <span>↓{formatRate(liveDl)} ↑{formatRate(liveUl)}</span>
                              </div>
                            )}
                          </div>
                        </Link>
                      )
                    })}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Top LAN Consumers Card */}
          <Card>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="p-1.5 rounded-md bg-blue-500/10 text-blue-600 dark:text-blue-400">
                    <Network className="w-4 h-4" />
                  </div>
                  <div>
                    <CardTitle className="text-sm font-semibold">Top Local (LAN) Consumers</CardTitle>
                    <CardDescription className="text-xs">Highest device-to-device traffic volume ({period})</CardDescription>
                  </div>
                </div>
                <Badge variant="outline" className="text-[10px] border-blue-500/30 bg-blue-500/10 text-blue-600 dark:text-blue-400 font-mono">
                  Internal
                </Badge>
              </div>
            </CardHeader>
            <CardContent>
              {topLanDevices.length === 0 ? (
                <div className="py-8 text-center text-xs text-muted-foreground">
                  No active LAN client traffic recorded for this period.
                </div>
              ) : (
                <div className="flex flex-col sm:flex-row items-center gap-5">
                  <div className="relative w-28 h-28 shrink-0 flex items-center justify-center">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={lanPieData}
                          dataKey="value"
                          nameKey="name"
                          innerRadius={28}
                          outerRadius={44}
                          paddingAngle={2}
                          stroke="transparent"
                        >
                          {lanPieData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} />
                          ))}
                        </Pie>
                      </PieChart>
                    </ResponsiveContainer>
                    <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none select-none text-center">
                      <span className="text-[9px] uppercase font-semibold text-muted-foreground">LAN</span>
                      <span className="text-xs font-bold font-mono text-foreground leading-none">
                        {formatBytes(Number(overview?.lan?.downloadBytes || 0) + Number(overview?.lan?.uploadBytes || 0))}
                      </span>
                    </div>
                  </div>

                  <div className="flex-1 w-full space-y-2 min-w-0">
                    {topLanDevices.map(({ device: d, dl, ul, total, liveDl, liveUl }, index) => {
                      const { icon: DevIcon } = getDeviceCategory(d.hostname, d.vendor)
                      const dName = d.hostname && !d.hostname.startsWith('unknown:') ? d.hostname : (d.vendor || d.ipAddr)
                      const liveRate = liveDl + liveUl
                      const color = DEVICE_PALETTE[index % DEVICE_PALETTE.length]

                      return (
                        <Link
                          key={d.ipAddr || index}
                          to={`/devices/${d.ipAddr}`}
                          className="flex items-center justify-between p-2 rounded-lg border bg-card/60 hover:bg-muted/40 hover:border-blue-500/40 transition-all group text-xs"
                        >
                          <div className="flex items-center gap-2 min-w-0 pr-2">
                            <span
                              className="w-2 h-2 rounded-full shrink-0"
                              style={{ backgroundColor: color }}
                            />
                            <span className="text-xs font-mono font-semibold text-muted-foreground w-3.5 text-center shrink-0">
                              #{index + 1}
                            </span>
                            <div className="p-1 rounded-md bg-muted text-muted-foreground group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors shrink-0">
                              <DevIcon className="w-3.5 h-3.5" />
                            </div>
                            <div className="min-w-0">
                              <div className="flex items-center gap-1.5">
                                <h4 className="text-xs font-semibold truncate text-foreground group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors">
                                  {dName}
                                </h4>
                                {d.vendor && dName !== d.vendor && (
                                  <span className="text-[10px] text-muted-foreground truncate hidden sm:inline">
                                    ({d.vendor})
                                  </span>
                                )}
                              </div>
                              <span className="text-[10px] font-mono text-muted-foreground block truncate">
                                {d.ipAddr}
                              </span>
                            </div>
                          </div>

                          <div className="text-right shrink-0">
                            <div className="text-xs font-mono font-bold text-foreground">
                              {formatBytes(total)}
                            </div>
                            <div className="text-[10px] font-mono text-muted-foreground flex items-center justify-end gap-1.5">
                              <span className="text-blue-600 dark:text-blue-400">↓ {formatBytes(dl)}</span>
                              <span className="text-indigo-600 dark:text-indigo-400">↑ {formatBytes(ul)}</span>
                            </div>
                            {liveRate > 0 && (
                              <div className="text-[10px] font-mono text-primary flex items-center justify-end gap-1 pt-0.5">
                                <span>Live:</span>
                                <span>↓{formatRate(liveDl)} ↑{formatRate(liveUl)}</span>
                              </div>
                            )}
                          </div>
                        </Link>
                      )
                    })}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  )
}
