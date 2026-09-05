import { useEffect, useState } from 'react'
import { ArrowDownCircle, ArrowUpCircle, Globe, Laptop, Clock } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from './ui/card'
import { Badge } from './ui/badge'
import { Button } from './ui/button'
import { formatBytes, formatRate, formatLatency } from '@/lib/format'
import { rpcClient } from '@/lib/client'
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
  LineChart,
  Line,
} from 'recharts'

export interface LivePoint {
  time: string
  download: number
  upload: number
}

interface OverviewTabProps {
  overview: any
  liveHistory: LivePoint[]
}

export function OverviewTab({ overview, liveHistory }: OverviewTabProps) {
  const [timeRange, setTimeRange] = useState<'15m' | '1h' | '6h' | '24h'>('1h')
  const [historyLoading, setHistoryLoading] = useState(false)
  const [historyData, setHistoryData] = useState<any[]>([])

  useEffect(() => {
    let active = true
    async function fetchHistory() {
      setHistoryLoading(true)
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
  }, [timeRange])

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
            <CardTitle className="text-sm font-medium">Download Rate</CardTitle>
            <ArrowDownCircle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold tracking-tight">
              {formatRate(overview?.currentDownloadBytesPerSec)}
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              Total: <span className="font-mono text-foreground font-medium">{formatBytes(overview?.totalDownloadBytes)}</span>
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
            <CardTitle className="text-sm font-medium">Upload Rate</CardTitle>
            <ArrowUpCircle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold tracking-tight">
              {formatRate(overview?.currentUploadBytesPerSec)}
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              Total: <span className="font-mono text-foreground font-medium">{formatBytes(overview?.totalUploadBytes)}</span>
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
            <CardTitle className="text-sm font-medium">Internet Health</CardTitle>
            <Globe className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="flex items-center space-x-2">
              <span className="text-2xl font-bold tracking-tight">
                {formatLatency(overview?.internetLatencySeconds)}
              </span>
              <Badge
                variant={overview?.internetIsUp ? "outline" : "destructive"}
                className={overview?.internetIsUp ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 font-normal" : "font-normal"}
              >
                {overview?.internetIsUp ? "Online" : "Offline"}
              </Badge>
            </div>
            <p className="text-xs text-muted-foreground mt-1">Average TCP reachability latency</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
            <CardTitle className="text-sm font-medium">Connected Devices</CardTitle>
            <Laptop className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold tracking-tight">
              {overview?.connectedDevicesCount || 0}
            </div>
            <p className="text-xs text-muted-foreground mt-1">Active ARP table entries</p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                Real-Time Bandwidth
                <Badge variant="outline" className="text-xs text-muted-foreground font-normal">
                  Rolling 60s
                </Badge>
              </CardTitle>
              <CardDescription>Live streaming network throughput across the router</CardDescription>
            </div>
            <div className="flex items-center space-x-4 text-xs">
              <div className="flex items-center gap-1.5">
                <span className="w-3 h-3 rounded-full bg-emerald-500 inline-block"></span>
                <span>Download ({formatRate(overview?.currentDownloadBytesPerSec)})</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-3 h-3 rounded-full bg-sky-500 inline-block"></span>
                <span>Upload ({formatRate(overview?.currentUploadBytesPerSec)})</span>
              </div>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="h-[260px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={liveHistory}>
                <defs>
                  <linearGradient id="dlGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#10b981" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#10b981" stopOpacity={0.0}/>
                  </linearGradient>
                  <linearGradient id="ulGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#0ea5e9" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#0ea5e9" stopOpacity={0.0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" opacity={0.5} />
                <XAxis dataKey="time" stroke="hsl(var(--muted-foreground))" fontSize={11} />
                <YAxis
                  stroke="hsl(var(--muted-foreground))"
                  fontSize={11}
                  tickFormatter={(val) => formatBytes(val)}
                  width={75}
                />
                <Tooltip
                  formatter={(val: any) => [formatRate(Number(val)), '']}
                  contentStyle={{
                    backgroundColor: 'hsl(var(--card))',
                    borderColor: 'hsl(var(--border))',
                    borderRadius: '8px',
                    color: 'hsl(var(--foreground))',
                    fontSize: '12px',
                  }}
                />
                <Area type="monotone" dataKey="download" stroke="#10b981" strokeWidth={2} fillOpacity={1} fill="url(#dlGrad)" isAnimationActive={false} name="Download" />
                <Area type="monotone" dataKey="upload" stroke="#0ea5e9" strokeWidth={2} fillOpacity={1} fill="url(#ulGrad)" isAnimationActive={false} name="Upload" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Clock className="w-5 h-5 text-primary" />
                Historical Traffic (SQLite TSDB)
              </CardTitle>
              <CardDescription>Persisted metrics stored and downsampled in embedded database</CardDescription>
            </div>
            <div className="flex items-center space-x-1 bg-muted p-1 rounded-lg">
              {(['15m', '1h', '6h', '24h'] as const).map((r) => (
                <Button
                  key={r}
                  variant={timeRange === r ? "default" : "ghost"}
                  size="sm"
                  className="h-7 text-xs px-2.5"
                  onClick={() => setTimeRange(r)}
                >
                  {r}
                </Button>
              ))}
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="h-[260px] w-full">
            {historyLoading && historyData.length === 0 ? (
              <div className="h-full flex items-center justify-center text-sm text-muted-foreground">
                Loading historical time series...
              </div>
            ) : historyData.length === 0 ? (
              <div className="h-full flex items-center justify-center text-sm text-muted-foreground">
                No historical records in TSDB for this window yet. Data is gathered every 5 seconds.
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={historyData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" opacity={0.5} />
                  <XAxis dataKey="time" stroke="hsl(var(--muted-foreground))" fontSize={11} />
                  <YAxis
                    stroke="hsl(var(--muted-foreground))"
                    fontSize={11}
                    tickFormatter={(val) => formatBytes(val)}
                    width={75}
                  />
                  <Tooltip
                    formatter={(val: any) => [formatRate(Number(val)), '']}
                    contentStyle={{
                      backgroundColor: 'hsl(var(--card))',
                      borderColor: 'hsl(var(--border))',
                      borderRadius: '8px',
                      color: 'hsl(var(--foreground))',
                      fontSize: '12px',
                    }}
                  />
                  <Line type="monotone" dataKey="download" stroke="#10b981" strokeWidth={2} dot={false} name="Download" />
                  <Line type="monotone" dataKey="upload" stroke="#0ea5e9" strokeWidth={2} dot={false} name="Upload" />
                </LineChart>
              </ResponsiveContainer>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
