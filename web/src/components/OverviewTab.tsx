import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { ArrowDownCircle, ArrowUpCircle, Globe, Laptop, Clock, ArrowDown, ArrowUp } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from './ui/card'
import { Badge } from './ui/badge'
import { formatBytes, formatRate, formatLatency } from '@/lib/format'
import { rpcClient } from '@/lib/client'
import { cn } from '@/lib/utils'
import { useRootOutletContext } from './RootLayout'
import { getPeriodRange } from '@/lib/period'
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
  ChartLegend,
  ChartLegendContent,
  type ChartConfig,
} from './ui/chart'

const trafficChartConfig = {
  download: {
    label: 'Download',
    color: '#10b981',
  },
  upload: {
    label: 'Upload',
    color: '#0ea5e9',
  },
} satisfies ChartConfig

interface OverviewTabProps {
  overview: any
}

export function OverviewTab({ overview }: OverviewTabProps) {
  const { period } = useRootOutletContext()
  const [historyLoading, setHistoryLoading] = useState(false)
  const [historyData, setHistoryData] = useState<any[]>([])

  useEffect(() => {
    let active = true
    async function fetchHistory() {
      setHistoryLoading(true)
      try {
        const { fromUnix: from, toUnix: now, stepSeconds: step } = getPeriodRange(period)

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

        if (!active) return

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
        console.error('Failed to load history from SQLite TSDB:', err)
      } finally {
        if (active) setHistoryLoading(false)
      }
    }

    fetchHistory()
    const interval = setInterval(fetchHistory, 15000)
    return () => {
      active = false
      clearInterval(interval)
    }
  }, [period])

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
            <CardTitle className="text-sm font-medium">Download Rate</CardTitle>
            <ArrowDownCircle className="h-4 w-4 text-emerald-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold font-mono tracking-tight">
              {formatRate(overview?.total?.downloadBytesPerSec)}
            </div>
            <div className="mt-2.5 pt-2 border-t space-y-1 text-xs">
              <div className="flex items-center justify-between text-muted-foreground">
                <span className="flex items-center gap-1 font-medium text-emerald-600 dark:text-emerald-400">
                  WAN (Internet):
                </span>
                <span className="font-mono font-medium text-foreground">
                  {formatRate(overview?.wan?.downloadBytesPerSec)}
                </span>
              </div>
              <div className="flex items-center justify-between text-muted-foreground">
                <span className="flex items-center gap-1 font-medium text-blue-600 dark:text-blue-400">
                  LAN (Local):
                </span>
                <span className="font-mono font-medium text-foreground">
                  {formatRate(overview?.lan?.downloadBytesPerSec)}
                </span>
              </div>
              <div className="pt-1 flex items-center justify-between text-[11px] text-muted-foreground">
                <span>Period Total ({period}):</span>
                <span className="font-mono text-foreground font-medium">
                  {formatBytes(overview?.total?.downloadBytes)}
                </span>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
            <CardTitle className="text-sm font-medium">Upload Rate</CardTitle>
            <ArrowUpCircle className="h-4 w-4 text-sky-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold font-mono tracking-tight">
              {formatRate(overview?.total?.uploadBytesPerSec)}
            </div>
            <div className="mt-2.5 pt-2 border-t space-y-1 text-xs">
              <div className="flex items-center justify-between text-muted-foreground">
                <span className="flex items-center gap-1 font-medium text-sky-600 dark:text-sky-400">
                  WAN (Internet):
                </span>
                <span className="font-mono font-medium text-foreground">
                  {formatRate(overview?.wan?.uploadBytesPerSec)}
                </span>
              </div>
              <div className="flex items-center justify-between text-muted-foreground">
                <span className="flex items-center gap-1 font-medium text-blue-600 dark:text-blue-400">
                  LAN (Local):
                </span>
                <span className="font-mono font-medium text-foreground">
                  {formatRate(overview?.lan?.uploadBytesPerSec)}
                </span>
              </div>
              <div className="pt-1 flex items-center justify-between text-[11px] text-muted-foreground">
                <span>Period Total ({period}):</span>
                <span className="font-mono text-foreground font-medium">
                  {formatBytes(overview?.total?.uploadBytes)}
                </span>
              </div>
            </div>
          </CardContent>
        </Card>

        <Link to="/health" className="block focus:outline-hidden">
          <Card className="hover:border-primary/50 transition-colors h-full">
            <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
              <CardTitle className="text-sm font-medium">Internet Health</CardTitle>
              <Globe className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="flex items-center space-x-2">
                <span className="text-2xl font-bold font-mono tracking-tight">
                  {formatLatency(overview?.internetLatencySeconds)}
                </span>
                <Badge
                  variant={overview?.internetStatus === 'down' || !overview?.internetIsUp ? "destructive" : "outline"}
                  className={cn(
                    "font-normal capitalize",
                    overview?.internetStatus === 'degraded' && "border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400",
                    (overview?.internetStatus === 'operational' || (!overview?.internetStatus && overview?.internetIsUp)) && "border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                  )}
                >
                  {overview?.internetStatus || (overview?.internetIsUp ? "Online" : "Offline")}
                </Badge>
              </div>
              <p className="text-xs text-muted-foreground mt-1">Multi-tier active probe latency</p>
            </CardContent>
          </Card>
        </Link>

        <Link to="/devices" className="block focus:outline-hidden">
          <Card className="hover:border-primary/50 transition-colors h-full">
            <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
              <CardTitle className="text-sm font-medium">Connected Devices</CardTitle>
              <Laptop className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold font-mono tracking-tight">
                {overview?.connectedDevicesCount || 0}
              </div>
              <p className="text-xs text-muted-foreground mt-1">Active ARP table entries</p>
            </CardContent>
          </Card>
        </Link>
      </div>

      {/* WAN & LAN Traffic Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* WAN Traffic Card */}
        <Card className="border-emerald-500/20 bg-gradient-to-br from-emerald-500/5 via-transparent to-transparent">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Globe className="h-4 w-4 text-emerald-500" />
                <CardTitle className="text-sm font-semibold">WAN Traffic (Internet)</CardTitle>
              </div>
              <Badge variant="outline" className="border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 font-mono text-[11px]">
                External
              </Badge>
            </div>
            <CardDescription className="text-xs">
              Direct traffic exchanged between your local network devices and the public Internet
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-2 gap-3 p-3 rounded-lg bg-muted/40 border border-border/50">
              <div>
                <span className="text-[11px] text-muted-foreground flex items-center gap-1">
                  <ArrowDown className="w-3 h-3 text-emerald-500" /> Download Rate
                </span>
                <div className="text-lg font-bold font-mono text-emerald-600 dark:text-emerald-400">
                  {formatRate(overview?.wan?.downloadBytesPerSec)}
                </div>
                <div className="text-[10px] text-muted-foreground mt-0.5">
                  Vol ({period}): <span className="font-mono">{formatBytes(overview?.wan?.downloadBytes)}</span>
                </div>
              </div>
              <div>
                <span className="text-[11px] text-muted-foreground flex items-center gap-1">
                  <ArrowUp className="w-3 h-3 text-sky-500" /> Upload Rate
                </span>
                <div className="text-lg font-bold font-mono text-sky-600 dark:text-sky-400">
                  {formatRate(overview?.wan?.uploadBytesPerSec)}
                </div>
                <div className="text-[10px] text-muted-foreground mt-0.5">
                  Vol ({period}): <span className="font-mono">{formatBytes(overview?.wan?.uploadBytes)}</span>
                </div>
              </div>
            </div>
            <div className="flex items-center justify-between text-xs pt-1 border-t">
              <span className="text-muted-foreground">Total WAN Volume ({period}):</span>
              <span className="font-mono font-semibold text-foreground">
                {formatBytes(Number(overview?.wan?.downloadBytes || 0) + Number(overview?.wan?.uploadBytes || 0))}
              </span>
            </div>
          </CardContent>
        </Card>

        {/* LAN Traffic Card */}
        <Card className="border-blue-500/20 bg-gradient-to-br from-blue-500/5 via-transparent to-transparent">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Laptop className="h-4 w-4 text-blue-500" />
                <CardTitle className="text-sm font-semibold">LAN Traffic (Device ↔ Device)</CardTitle>
              </div>
              <Badge variant="outline" className="border-blue-500/30 bg-blue-500/10 text-blue-600 dark:text-blue-400 text-[11px]">
                Internal
              </Badge>
            </div>
            <CardDescription className="text-xs">
              Subnet traffic passing between local devices within your LAN
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-2 gap-3 p-3 rounded-lg bg-muted/40 border border-border/50">
              <div>
                <span className="text-[11px] text-muted-foreground flex items-center gap-1">
                  <ArrowDown className="w-3 h-3 text-blue-500" /> Ingress Rate
                </span>
                <div className="text-lg font-bold font-mono text-blue-600 dark:text-blue-400">
                  {formatRate(overview?.lan?.downloadBytesPerSec)}
                </div>
                <div className="text-[10px] text-muted-foreground mt-0.5">
                  Vol ({period}): <span className="font-mono">{formatBytes(overview?.lan?.downloadBytes)}</span>
                </div>
              </div>
              <div>
                <span className="text-[11px] text-muted-foreground flex items-center gap-1">
                  <ArrowUp className="w-3 h-3 text-indigo-500" /> Egress Rate
                </span>
                <div className="text-lg font-bold font-mono text-indigo-600 dark:text-indigo-400">
                  {formatRate(overview?.lan?.uploadBytesPerSec)}
                </div>
                <div className="text-[10px] text-muted-foreground mt-0.5">
                  Vol ({period}): <span className="font-mono">{formatBytes(overview?.lan?.uploadBytes)}</span>
                </div>
              </div>
            </div>
            <div className="flex items-center justify-between text-xs pt-1 border-t">
              <span className="text-muted-foreground">Total LAN Volume ({period}):</span>
              <span className="font-mono font-semibold text-foreground">
                {formatBytes(Number(overview?.lan?.downloadBytes || 0) + Number(overview?.lan?.uploadBytes || 0))}
              </span>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Clock className="w-5 h-5 text-primary" />
                Network Bandwidth
              </CardTitle>
              <CardDescription>Persisted metrics sampled and downsampled in embedded SQLite TSDB</CardDescription>
            </div>
            <div className="flex flex-wrap items-center gap-3">
              <div className="flex items-center space-x-3 text-xs">
                <div className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 inline-block"></span>
                  <span className="text-muted-foreground">Down:</span>
                  <span className="font-mono font-medium text-emerald-600 dark:text-emerald-400">{formatRate(overview?.total?.downloadBytesPerSec)}</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-sky-500 inline-block"></span>
                  <span className="text-muted-foreground">Up:</span>
                  <span className="font-mono font-medium text-sky-600 dark:text-sky-400">{formatRate(overview?.total?.uploadBytesPerSec)}</span>
                </div>
                <Badge variant="outline" className="font-mono text-xs px-2 py-0.5">
                  {period}
                </Badge>
              </div>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="h-[280px] w-full">
            {historyLoading && historyData.length === 0 ? (
              <div className="h-full flex items-center justify-center text-sm text-muted-foreground">
                Loading historical time series...
              </div>
            ) : historyData.length === 0 ? (
              <div className="h-full flex items-center justify-center text-sm text-muted-foreground">
                No historical records in TSDB for this window yet. Data is gathered every 15 seconds.
              </div>
            ) : (
              <ChartContainer config={trafficChartConfig} className="h-[280px] w-full aspect-auto">
                <AreaChart data={historyData}>
                  <defs>
                    <linearGradient id="dlGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="var(--color-download)" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="var(--color-download)" stopOpacity={0.0} />
                    </linearGradient>
                    <linearGradient id="ulGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="var(--color-upload)" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="var(--color-upload)" stopOpacity={0.0} />
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
                                {trafficChartConfig[name as keyof typeof trafficChartConfig]?.label ?? name}
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
                    stroke="var(--color-download)"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#dlGrad)"
                  />
                  <Area
                    type="monotone"
                    dataKey="upload"
                    stroke="var(--color-upload)"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#ulGrad)"
                  />
                  <ChartLegend content={<ChartLegendContent className="text-xs pt-3" />} />
                </AreaChart>
              </ChartContainer>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
