import { useEffect, useState } from 'react'
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
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from 'recharts'

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
          const targetName = s.labels['target'] || 'target'
          for (const pt of s.points) {
            const ts = Number(pt.timestampUnix)
            let entry = timeMap.get(ts)
            if (!entry) {
              const d = new Date(ts * 1000)
              entry = { time: d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) }
              timeMap.set(ts, entry)
            }
            entry[targetName] = Number((pt.value * 1000).toFixed(1))
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
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={latencyHistory}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" opacity={0.5} />
                  <XAxis dataKey="time" stroke="hsl(var(--muted-foreground))" fontSize={11} />
                  <YAxis
                    stroke="hsl(var(--muted-foreground))"
                    fontSize={11}
                    unit="ms"
                    width={50}
                  />
                  <Tooltip
                    formatter={(val: any) => [`${val} ms`, '']}
                    contentStyle={{
                      backgroundColor: 'hsl(var(--card))',
                      borderColor: 'hsl(var(--border))',
                      borderRadius: '8px',
                      color: 'hsl(var(--foreground))',
                      fontSize: '12px',
                    }}
                  />
                  {targets.map((t: any, i: number) => {
                    const colors = ['#10b981', '#0ea5e9', '#8b5cf6', '#f59e0b']
                    return (
                      <Line
                        key={t.addr}
                        type="monotone"
                        dataKey={t.addr}
                        stroke={colors[i % colors.length]}
                        strokeWidth={2}
                        dot={false}
                        name={t.addr}
                      />
                    )
                  })}
                </LineChart>
              </ResponsiveContainer>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
