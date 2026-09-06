export type Period = '15m' | '1h' | '6h' | '24h'

export const PERIODS: readonly Period[] = ['15m', '1h', '6h', '24h'] as const

export function isPeriod(val: string | null): val is Period {
  return val === '15m' || val === '1h' || val === '6h' || val === '24h'
}

export function getPeriodRange(period: Period): { fromUnix: number; toUnix: number; stepSeconds: number } {
  const now = Math.floor(Date.now() / 1000)
  switch (period) {
    case '15m':
      return { fromUnix: now - 900, toUnix: now, stepSeconds: 5 }
    case '6h':
      return { fromUnix: now - 21600, toUnix: now, stepSeconds: 60 }
    case '1h':
      return { fromUnix: now - 3600, toUnix: now, stepSeconds: 15 }
    case '24h':
    default:
      return { fromUnix: now - 86400, toUnix: now, stepSeconds: 300 }
  }
}
