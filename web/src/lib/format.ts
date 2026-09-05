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

export function formatLatency(sec: number | undefined | null): string {
  if (sec === undefined || sec === null || sec <= 0) return "--"
  const ms = sec * 1000
  if (ms < 1) return `${(ms).toFixed(2)} ms`
  return `${ms.toFixed(1)} ms`
}
