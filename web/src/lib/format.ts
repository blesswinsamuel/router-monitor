export function formatBytes(bytes: number | bigint | undefined | null): string {
  if (bytes === undefined || bytes === null) return "0 B"
  const n = Number(bytes)
  if (n === 0) return "0 B"
  const k = 1024
  const sizes = ["B", "KB", "MB", "GB", "TB", "PB"]
  const i = Math.floor(Math.log(n) / Math.log(k))
  return `${parseFloat((n / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`
}

export function formatRate(bytesPerSec: number | undefined | null): string {
  if (!bytesPerSec || bytesPerSec <= 0) return "0 B/s"
  return `${formatBytes(bytesPerSec)}/s`
}

export function formatPackets(pkts: number | bigint | undefined | null): string {
  if (!pkts) return "0"
  const n = Number(pkts)
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`
  return n.toLocaleString()
}

export function formatPacketsRate(pktsPerSec: number | undefined | null): string {
  if (!pktsPerSec || pktsPerSec <= 0) return "0 pps"
  return `${formatPackets(pktsPerSec)} pps`
}

export function formatLatency(sec: number | undefined | null): string {
  if (sec === undefined || sec === null || sec <= 0) return "--"
  const ms = sec * 1000
  if (ms < 1) return `${(ms).toFixed(2)} ms`
  return `${ms.toFixed(1)} ms`
}

export function formatRelativeTime(unixSeconds: number | bigint | undefined | null): string {
  if (!unixSeconds) return "Never"
  const sec = Number(unixSeconds)
  if (sec <= 0) return "Never"
  const diffSec = Math.floor(Date.now() / 1000) - sec
  if (diffSec < 10) return "just now"
  if (diffSec < 60) return `${diffSec}s ago`
  const min = Math.floor(diffSec / 60)
  if (min < 60) return `${min}m ago`
  const hr = Math.floor(min / 60)
  if (hr < 24) return `${hr}h ago`
  const days = Math.floor(hr / 24)
  return `${days}d ago`
}

export function formatDateTime(unixSeconds: number | bigint | undefined | null): string {
  if (!unixSeconds) return "--"
  const sec = Number(unixSeconds)
  if (sec <= 0) return "--"
  return new Date(sec * 1000).toLocaleString()
}

export function formatDuration(sec: number | undefined | null): string {
  if (!sec || sec <= 0) return "0s"
  const s = Math.round(sec)
  if (s < 60) return `${s}s`
  const m = Math.floor(s / 60)
  const remS = s % 60
  if (m < 60) return remS > 0 ? `${m}m ${remS}s` : `${m}m`
  const h = Math.floor(m / 60)
  const remM = m % 60
  return remM > 0 ? `${h}h ${remM}m` : `${h}h`
}

export function formatPercent(ratio: number | undefined | null): string {
  if (ratio === undefined || ratio === null || isNaN(ratio)) return "0.0%"
  return `${(ratio * 100).toFixed(1)}%`
}

export function formatChartTime(date: Date, period?: string): string {
  if (period === '3d' || period === '7d') {
    return `${date.toLocaleDateString([], { month: 'short', day: 'numeric' })} ${date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`
  }
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

