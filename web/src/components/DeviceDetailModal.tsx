import { useEffect, useState } from 'react'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from './ui/dialog'
import { Badge } from './ui/badge'
import { Button } from './ui/button'
import { Card, CardContent } from './ui/card'
import {
  Clock,
  Globe,
  HardDrive,
  Laptop,
  Network,
  Activity,
} from 'lucide-react'
import { formatBytes, formatRate, formatRelativeTime } from '@/lib/format'
import { rpcClient } from '@/lib/client'
import { cn } from '@/lib/utils'
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
} from './ui/chart'

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

interface DeviceDetailModalProps {
  device: any | null
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function DeviceDetailModal({ device, open, onOpenChange }: DeviceDetailModalProps) {
  const [timeRange, setTimeRange] = useState<'15m' | '1h' | '6h' | '24h'>('1h')
  const [loading, setLoading] = useState(false)
  const [historyData, setHistoryData] = useState<{ time: string; download: number; upload: number }[]>([])

  useEffect(() => {
    if (!open || !device?.ipAddr) {
      setHistoryData([])
      return
    }

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

        const [dlRes, ulRes] = await Promise.all([
          rpcClient.queryTimeSeries({
            metricName: 'device_traffic_bytes_rate',
            matchLabels: { ip: device.ipAddr, direction: 'ingress' },
            fromUnix: BigInt(from),
            toUnix: BigInt(now),
            stepSeconds: step,
          }),
          rpcClient.queryTimeSeries({
            metricName: 'device_traffic_bytes_rate',
            matchLabels: { ip: device.ipAddr, direction: 'egress' },
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
        console.error('Failed to load device history:', err)
      } finally {
        if (active) setLoading(false)
      }
    }

    fetchDeviceHistory()

    return () => {
      active = false
    }
  }, [open, device?.ipAddr, timeRange])

  if (!device) return null

  const status = device.status || (device.isValid ? 'active' : 'unreachable')
  const isOnline = status === 'active' || status === 'static'
  const dlRate = Number(device.currentDownloadBytesPerSec || 0)
  const ulRate = Number(device.currentUploadBytesPerSec || 0)
  const wanDlRate = Number(device.currentWanDownloadBytesPerSec || 0)
  const wanUlRate = Number(device.currentWanUploadBytesPerSec || 0)
  const lanDlRate = Number(device.currentLanDownloadBytesPerSec || 0)
  const lanUlRate = Number(device.currentLanUploadBytesPerSec || 0)

  const internetDl = Number(device.internetDownloadBytes || 0)
  const internetUl = Number(device.internetUploadBytes || 0)
  const lanDl = Number(device.lanDownloadBytes || 0)
  const lanUl = Number(device.lanUploadBytes || 0)
  const totalDl = Number(device.downloadBytes || (internetDl + lanDl))
  const totalUl = Number(device.uploadBytes || (internetUl + lanUl))

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-5xl md:max-w-5xl lg:max-w-6xl w-[95vw] max-h-[90vh] overflow-y-auto">
        <DialogHeader className="space-y-2 border-b pb-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-lg bg-primary/10 text-primary">
                <Laptop className="w-5 h-5" />
              </div>
              <div>
                <DialogTitle className="text-lg font-semibold flex items-center gap-2">
                  <span>
                    {device.hostname && !device.hostname.startsWith('unknown:')
                      ? device.hostname
                      : 'Unknown Device'}
                  </span>
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
                </DialogTitle>
                <DialogDescription className="font-mono text-xs flex flex-wrap items-center gap-x-3 gap-y-1 mt-0.5">
                  <span>IP: <strong className="text-foreground">{device.ipAddr}</strong></span>
                  <span>MAC: <strong className="text-foreground">{device.hwAddr}</strong></span>
                  <span>Interface: <strong className="text-foreground">{device.device || 'lan'}</strong></span>
                </DialogDescription>
              </div>
            </div>

            {/* Live Throughput if online */}
            {isOnline && (dlRate > 0 || ulRate > 0) && (
              <div className="flex flex-wrap items-center gap-2 self-start sm:self-center">
                {(wanDlRate > 0 || wanUlRate > 0) && (
                  <div className="flex items-center gap-1.5 px-2 py-1 rounded-md bg-muted/60 text-xs font-mono">
                    <Globe className="w-3 h-3 text-primary" />
                    <span className="text-muted-foreground text-[10px]">WAN:</span>
                    <span className="text-emerald-500 font-semibold">↓ {formatRate(wanDlRate)}</span>
                    <span className="text-sky-500 font-semibold">↑ {formatRate(wanUlRate)}</span>
                  </div>
                )}
                {(lanDlRate > 0 || lanUlRate > 0) && (
                  <div className="flex items-center gap-1.5 px-2 py-1 rounded-md bg-muted/60 text-xs font-mono">
                    <Network className="w-3 h-3 text-sky-500" />
                    <span className="text-muted-foreground text-[10px]">LAN:</span>
                    <span className="text-emerald-500 font-semibold">↓ {formatRate(lanDlRate)}</span>
                    <span className="text-sky-500 font-semibold">↑ {formatRate(lanUlRate)}</span>
                  </div>
                )}
              </div>
            )}
          </div>
        </DialogHeader>

        {/* Traffic Breakdown Summary Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 my-2">
          {/* Internet Traffic */}
          <Card className="bg-muted/30 border-muted">
            <CardContent className="p-3.5 space-y-2">
              <div className="flex items-center justify-between text-xs font-medium text-muted-foreground">
                <span className="flex items-center gap-1.5">
                  <Globe className="w-3.5 h-3.5 text-primary" />
                  Internet Traffic (WAN)
                </span>
                {(wanDlRate > 0 || wanUlRate > 0) && (
                  <Badge variant="outline" className="text-[10px] px-1.5 py-0 border-primary/30 text-primary">
                    Live: {formatRate(wanDlRate + wanUlRate)}
                  </Badge>
                )}
              </div>
              <div className="grid grid-cols-2 gap-2 text-xs font-mono pt-1">
                <div>
                  <span className="text-muted-foreground text-[11px] block">Download</span>
                  <span className="font-semibold text-emerald-500 text-sm">{formatBytes(internetDl)}</span>
                  <span className="text-[10px] text-muted-foreground block">{formatRate(wanDlRate)}</span>
                </div>
                <div>
                  <span className="text-muted-foreground text-[11px] block">Upload</span>
                  <span className="font-semibold text-sky-500 text-sm">{formatBytes(internetUl)}</span>
                  <span className="text-[10px] text-muted-foreground block">{formatRate(wanUlRate)}</span>
                </div>
              </div>
              <div className="text-[11px] text-muted-foreground pt-1.5 border-t border-border/50 flex justify-between">
                <span>Total WAN:</span>
                <strong className="text-foreground">{formatBytes(internetDl + internetUl)}</strong>
              </div>
            </CardContent>
          </Card>

          {/* Local LAN Traffic */}
          <Card className="bg-muted/30 border-muted">
            <CardContent className="p-3.5 space-y-2">
              <div className="flex items-center justify-between text-xs font-medium text-muted-foreground">
                <span className="flex items-center gap-1.5">
                  <Network className="w-3.5 h-3.5 text-sky-500" />
                  Local Traffic (Device ↔ Device)
                </span>
                {(lanDlRate > 0 || lanUlRate > 0) && (
                  <Badge variant="outline" className="text-[10px] px-1.5 py-0 border-sky-500/30 text-sky-500">
                    Live: {formatRate(lanDlRate + lanUlRate)}
                  </Badge>
                )}
              </div>
              <div className="grid grid-cols-2 gap-2 text-xs font-mono pt-1">
                <div>
                  <span className="text-muted-foreground text-[11px] block">Download</span>
                  <span className="font-semibold text-emerald-500 text-sm">{formatBytes(lanDl)}</span>
                  <span className="text-[10px] text-muted-foreground block">{formatRate(lanDlRate)}</span>
                </div>
                <div>
                  <span className="text-muted-foreground text-[11px] block">Upload</span>
                  <span className="font-semibold text-sky-500 text-sm">{formatBytes(lanUl)}</span>
                  <span className="text-[10px] text-muted-foreground block">{formatRate(lanUlRate)}</span>
                </div>
              </div>
              <div className="text-[11px] text-muted-foreground pt-1.5 border-t border-border/50 flex justify-between">
                <span>Total LAN:</span>
                <strong className="text-foreground">{formatBytes(lanDl + lanUl)}</strong>
              </div>
            </CardContent>
          </Card>

          {/* Total & Timestamps */}
          <Card className="bg-muted/30 border-muted">
            <CardContent className="p-3.5 space-y-2">
              <div className="flex items-center justify-between text-xs font-medium text-muted-foreground">
                <span className="flex items-center gap-1.5">
                  <HardDrive className="w-3.5 h-3.5 text-muted-foreground" />
                  Lifetime Volume
                </span>
                {(dlRate > 0 || ulRate > 0) && (
                  <Badge variant="outline" className="text-[10px] px-1.5 py-0 border-emerald-500/30 text-emerald-600 dark:text-emerald-400">
                    Live: {formatRate(dlRate + ulRate)}
                  </Badge>
                )}
              </div>
              <div className="grid grid-cols-2 gap-2 text-xs font-mono pt-1">
                <div>
                  <span className="text-muted-foreground text-[11px] block">Total In</span>
                  <span className="font-semibold text-emerald-500 text-sm">{formatBytes(totalDl)}</span>
                  <span className="text-[10px] text-muted-foreground block">{formatRate(dlRate)}</span>
                </div>
                <div>
                  <span className="text-muted-foreground text-[11px] block">Total Out</span>
                  <span className="font-semibold text-sky-500 text-sm">{formatBytes(totalUl)}</span>
                  <span className="text-[10px] text-muted-foreground block">{formatRate(ulRate)}</span>
                </div>
              </div>
              <div className="text-[11px] text-muted-foreground pt-1.5 border-t border-border/50 flex items-center justify-between">
                <span>Last seen:</span>
                <strong className="text-foreground">{formatRelativeTime(device.lastSeenUnix)}</strong>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Time Series Historical Bandwidth Chart */}
        <div className="space-y-3 pt-2">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <Clock className="w-4 h-4 text-primary" />
              <h4 className="text-sm font-semibold">Bandwidth History</h4>
              {loading && <span className="text-xs text-muted-foreground animate-pulse">Loading...</span>}
            </div>
            <div className="flex items-center gap-1 bg-muted/60 p-0.5 rounded-lg">
              {(['15m', '1h', '6h', '24h'] as const).map((r) => (
                <Button
                  key={r}
                  variant={timeRange === r ? 'secondary' : 'ghost'}
                  size="sm"
                  className="h-7 text-xs px-2.5"
                  onClick={() => setTimeRange(r)}
                >
                  {r}
                </Button>
              ))}
            </div>
          </div>

          <div className="rounded-lg border bg-card p-3">
            {historyData.length === 0 ? (
              <div className="h-56 flex flex-col items-center justify-center text-muted-foreground text-xs text-center px-4">
                <Activity className="w-8 h-8 opacity-25 mb-2" />
                <span>No historical time series samples recorded for this device in the last {timeRange}.</span>
                <span className="text-[11px] opacity-75 mt-1">Data begins recording as soon as the device transmits network traffic.</span>
              </div>
            ) : (
              <ChartContainer config={deviceChartConfig} className="h-56 w-full">
                <AreaChart data={historyData} margin={{ top: 10, right: 10, left: -10, bottom: 0 }}>
                  <defs>
                    <linearGradient id="dev-dl-grad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#10b981" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#10b981" stopOpacity={0.0} />
                    </linearGradient>
                    <linearGradient id="dev-ul-grad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#0ea5e9" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#0ea5e9" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" vertical={false} className="stroke-muted/40" />
                  <XAxis dataKey="time" tickLine={false} axisLine={false} tickMargin={8} minTickGap={32} className="text-[10px]" />
                  <YAxis tickLine={false} axisLine={false} tickFormatter={(val) => formatRate(val)} className="text-[10px]" />
                  <ChartTooltip content={<ChartTooltipContent formatter={(val) => formatRate(Number(val))} />} />
                  <Area
                    type="monotone"
                    dataKey="download"
                    name="Download"
                    stroke="#10b981"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#dev-dl-grad)"
                  />
                  <Area
                    type="monotone"
                    dataKey="upload"
                    name="Upload"
                    stroke="#0ea5e9"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#dev-ul-grad)"
                  />
                </AreaChart>
              </ChartContainer>
            )}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}
