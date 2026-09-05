import { useEffect, useMemo, useState } from 'react'
import { CheckCircle2, XCircle, Activity } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from './ui/card'
import { Badge } from './ui/badge'
import { formatLatency } from '@/lib/format'
import { rpcClient } from '@/lib/client'
import {
  LineChart,
  Line,
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

function safeKey(addr: string): string {
  return addr.replace(/[^a-zA-Z0-9_-]/g, '_')
}

const PALETTE = ['#10b981', '#0ea5e9', '#8b5cf6', '#f59e0b', '#ec4899', '#06b6d4']

interface InternetHealthTabProps {
  health: any
}

export function InternetHealthTab({ health }: InternetHealthTabProps) {
  const [latencyHistory, setLatencyHistory] = useState<any[]>([])

  useEffect(() => {
    let active = true
    async function fetchLatencyHistory() {
      try {
        const now = Math.floor(Date.now() / 1000)
        const from = now - 3600 // last 1 hour

        const res = await rpcClient.queryTimeSeries({
          metricName: 'internet_latency_seconds',
          matchLabels: {},
          fromUnix: BigInt(from),
          toUnix: BigInt(now),
          stepSeconds: 30,
        })

        if (!active) return

        const timeMap = new Map<number, any>()

        for (const s of res.series) {
          const rawTarget = s.labels['target'] || 'target'
          const targetKey = safeKey(rawTarget)
          for (const pt of s.points) {
            const ts = Number(pt.timestampUnix)
            let entry = timeMap.get(ts)
            if (!entry) {
              const d = new Date(ts * 1000)
              entry = { time: d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) }
              timeMap.set(ts, entry)
            }
            entry[targetKey] = Number((pt.value * 1000).toFixed(1))
          }
        }

        const sorted = Array.from(timeMap.entries())
          .sort(([a], [b]) => a - b)
          .map(([_, v]) => v)

        setLatencyHistory(sorted)
      } catch (err) {
        console.error('Failed to load latency history:', err)
      }
    }

    fetchLatencyHistory()
    const interval = setInterval(fetchLatencyHistory, 15000)
    return () => {
      active = false
      clearInterval(interval)
    }
  }, [])

  const targets = health?.targets || []

  const chartConfig = useMemo(() => {
    const config: ChartConfig = {}
    targets.forEach((t: any, idx: number) => {
      config[safeKey(t.addr)] = {
        label: t.addr,
        color: PALETTE[idx % PALETTE.length],
      }
    })
    return config
  }, [targets])

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {targets.map((t: any, idx: number) => {
          const isUp = t.isUp
          return (
            <Card key={`${t.addr}-${idx}`}>
              <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
                <CardTitle className="text-sm font-medium font-mono">{t.addr}</CardTitle>
                {isUp ? (
                  <CheckCircle2 className="w-5 h-5 text-emerald-500" />
                ) : (
                  <XCircle className="w-5 h-5 text-destructive" />
                )}
              </CardHeader>
              <CardContent>
                <div className="flex items-baseline justify-between">
                  <div className="text-2xl font-bold font-mono">
                    {formatLatency(t.lastLatencySeconds)}
                  </div>
                  <Badge
                    variant={isUp ? "outline" : "destructive"}
                    className={isUp ? "border-emerald-500/20 bg-emerald-500/15 text-emerald-600 dark:text-emerald-400" : ""}
                  >
                    {isUp ? "Up" : "Down"}
                  </Badge>
                </div>
                <div className="flex items-center justify-between mt-2 text-xs text-muted-foreground">
                  <span>Avg Latency:</span>
                  <span className="font-mono font-semibold text-foreground">
                    {formatLatency(t.avgLatencySeconds)}
                  </span>
                </div>
              </CardContent>
            </Card>
          )
        })}
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Activity className="w-5 h-5 text-primary" />
            Connection Latency History (1h)
          </CardTitle>
          <CardDescription>
            TCP round-trip latency (in milliseconds) across configured targets
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="h-[280px] w-full">
            {latencyHistory.length === 0 ? (
              <div className="h-full flex items-center justify-center text-sm text-muted-foreground">
                Collecting latency time series into SQLite database...
              </div>
            ) : (
              <ChartContainer config={chartConfig} className="h-[280px] w-full aspect-auto">
                <LineChart data={latencyHistory}>
                  <CartesianGrid strokeDasharray="3 3" vertical={false} />
                  <XAxis dataKey="time" tickLine={false} axisLine={false} tickMargin={8} fontSize={11} />
                  <YAxis
                    tickLine={false}
                    axisLine={false}
                    fontSize={11}
                    unit="ms"
                    width={50}
                  />
                  <ChartTooltip
                    cursor={false}
                    content={
                      <ChartTooltipContent
                        indicator="dot"
                        formatter={(val, name, item) => (
                          <>
                            <div
                              className="h-2.5 w-2.5 shrink-0 rounded-[2px]"
                              style={{ backgroundColor: item.color }}
                            />
                            <div className="flex flex-1 justify-between items-center leading-none gap-2">
                              <span className="text-muted-foreground font-mono">
                                {chartConfig[name as keyof typeof chartConfig]?.label ?? name}
                              </span>
                              <span className="font-mono font-medium text-foreground tabular-nums">
                                {val} ms
                              </span>
                            </div>
                          </>
                        )}
                      />
                    }
                  />
                  {targets.map((t: any) => {
                    const key = safeKey(t.addr)
                    return (
                      <Line
                        key={t.addr}
                        type="monotone"
                        dataKey={key}
                        stroke={`var(--color-${key})`}
                        strokeWidth={2}
                        dot={false}
                        name={key}
                      />
                    )
                  })}
                </LineChart>
              </ChartContainer>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
