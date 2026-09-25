import { useState } from 'react'
import {
  Globe,
  RefreshCw,
  Copy,
  Check,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Clock,
  Radio,
  Server,
  ExternalLink,
} from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { formatDateTime, formatRelativeTime } from '@/lib/format'
import { rpcClient } from '@/lib/client'
import { useRootOutletContext } from '@/components/RootLayout'
import { cn } from '@/lib/utils'

export function DDNSPage() {
  const { ddns, fetchAllData } = useRootOutletContext()
  const [isSyncing, setIsSyncing] = useState(false)
  const [syncFeedback, setSyncFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null)
  const [copiedKey, setCopiedKey] = useState<string | null>(null)

  const handleCopy = (text: string, key: string) => {
    if (!text) return
    navigator.clipboard.writeText(text)
    setCopiedKey(key)
    setTimeout(() => setCopiedKey(null), 2000)
  }

  const handleForceSync = async () => {
    setIsSyncing(true)
    setSyncFeedback(null)
    try {
      const res = await rpcClient.syncDDNS({ force: true })
      if (res.success) {
        setSyncFeedback({ type: 'success', message: res.message || 'DDNS synchronized successfully' })
      } else {
        setSyncFeedback({ type: 'error', message: res.message || 'Failed to sync DDNS' })
      }
      await fetchAllData()
    } catch (err: any) {
      setSyncFeedback({ type: 'error', message: err?.message || 'Sync request failed' })
    } finally {
      setIsSyncing(false)
    }
  }

  const isEnabled = ddns?.enabled ?? false
  const status = ddns?.lastSyncStatus || (isEnabled ? 'pending' : 'disabled')
  const provider = ddns?.provider || 'none'
  const domains: string[] = ddns?.domains || []
  const ipv4 = ddns?.currentIpv4 || ''
  const ipv6 = ddns?.currentIpv6 || ''
  const lastSyncUnix = Number(ddns?.lastSyncUnix || 0)
  const lastMessage = ddns?.lastSyncMessage || ''
  const intervalSec = Number(ddns?.checkIntervalSeconds || 300)
  const history: any[] = ddns?.history || []

  const isSuccess = status === 'success'
  const isFailed = status === 'failure'
  const isPending = status === 'pending'

  return (
    <div className="space-y-6">
      {/* Top Banner / Actions Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold tracking-tight flex items-center gap-2">
            <Globe className="w-6 h-6 text-primary" />
            Dynamic DNS (DDNS)
          </h2>
          <p className="text-sm text-muted-foreground mt-1">
            Automatically keep your public DNS records synchronized with your router's WAN IP.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            onClick={handleForceSync}
            disabled={isSyncing || !isEnabled}
            className="gap-2"
            size="sm"
          >
            <RefreshCw className={cn("w-4 h-4", isSyncing && "animate-spin")} />
            {isSyncing ? 'Syncing...' : 'Force Sync Now'}
          </Button>
        </div>
      </div>

      {/* Sync Feedback Banner */}
      {syncFeedback && (
        <div
          className={cn(
            "p-3 rounded-lg text-sm flex items-center justify-between border",
            syncFeedback.type === 'success'
              ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-600 dark:text-emerald-400"
              : "bg-destructive/10 border-destructive/20 text-destructive"
          )}
        >
          <div className="flex items-center gap-2">
            {syncFeedback.type === 'success' ? (
              <CheckCircle2 className="w-4 h-4 shrink-0" />
            ) : (
              <AlertTriangle className="w-4 h-4 shrink-0" />
            )}
            <span>{syncFeedback.message}</span>
          </div>
          <button
            onClick={() => setSyncFeedback(null)}
            className="text-xs underline hover:opacity-80 ml-4 cursor-pointer"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Status Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* IPv4 Card */}
        <Card className="shadow-xs">
          <CardHeader className="pb-2 flex flex-row items-center justify-between space-y-0">
            <CardTitle className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Public WAN IPv4
            </CardTitle>
            <Radio className="w-4 h-4 text-sky-500" />
          </CardHeader>
          <CardContent>
            <div className="flex items-baseline justify-between gap-2">
              <span className="font-mono text-lg font-bold truncate">
                {ipv4 || <span className="text-muted-foreground text-sm font-normal">Not detected</span>}
              </span>
              {ipv4 && (
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-7 w-7 shrink-0 cursor-pointer"
                  onClick={() => handleCopy(ipv4, 'ipv4')}
                  title="Copy IPv4"
                >
                  {copiedKey === 'ipv4' ? (
                    <Check className="w-3.5 h-3.5 text-emerald-500" />
                  ) : (
                    <Copy className="w-3.5 h-3.5 text-muted-foreground" />
                  )}
                </Button>
              )}
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              {ipv4 ? 'A Record Target' : 'Check network reachability'}
            </p>
          </CardContent>
        </Card>

        {/* IPv6 Card */}
        <Card className="shadow-xs">
          <CardHeader className="pb-2 flex flex-row items-center justify-between space-y-0">
            <CardTitle className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Public WAN IPv6
            </CardTitle>
            <Server className="w-4 h-4 text-indigo-500" />
          </CardHeader>
          <CardContent>
            <div className="flex items-baseline justify-between gap-2">
              <span className="font-mono text-xs font-bold truncate max-w-[180px]" title={ipv6 || undefined}>
                {ipv6 || <span className="text-muted-foreground font-normal">None detected</span>}
              </span>
              {ipv6 && (
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-7 w-7 shrink-0 cursor-pointer"
                  onClick={() => handleCopy(ipv6, 'ipv6')}
                  title="Copy IPv6"
                >
                  {copiedKey === 'ipv6' ? (
                    <Check className="w-3.5 h-3.5 text-emerald-500" />
                  ) : (
                    <Copy className="w-3.5 h-3.5 text-muted-foreground" />
                  )}
                </Button>
              )}
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              {ipv6 ? 'AAAA Record Target' : 'IPv6 disabled or unassigned'}
            </p>
          </CardContent>
        </Card>

        {/* Provider & State */}
        <Card className="shadow-xs">
          <CardHeader className="pb-2 flex flex-row items-center justify-between space-y-0">
            <CardTitle className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Sync Status
            </CardTitle>
            {isSuccess && <CheckCircle2 className="w-4 h-4 text-emerald-500" />}
            {isFailed && <XCircle className="w-4 h-4 text-destructive" />}
            {isPending && <Clock className="w-4 h-4 text-amber-500" />}
            {!isEnabled && <Radio className="w-4 h-4 text-muted-foreground" />}
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2">
              {isSuccess && (
                <Badge variant="outline" className="border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
                  Synchronized
                </Badge>
              )}
              {isFailed && (
                <Badge variant="destructive">
                  Sync Failed
                </Badge>
              )}
              {isPending && (
                <Badge variant="secondary" className="bg-amber-500/10 text-amber-600 dark:text-amber-400">
                  Pending
                </Badge>
              )}
              {!isEnabled && (
                <Badge variant="secondary" className="text-muted-foreground">
                  Disabled
                </Badge>
              )}
              <span className="text-xs font-mono capitalize text-muted-foreground">
                {provider}
              </span>
            </div>
            <p className="text-xs text-muted-foreground mt-2 truncate" title={lastMessage || undefined}>
              {lastMessage || (isEnabled ? 'Running on schedule' : 'DDNS_PROVIDER not configured')}
            </p>
          </CardContent>
        </Card>

        {/* Last Synced */}
        <Card className="shadow-xs">
          <CardHeader className="pb-2 flex flex-row items-center justify-between space-y-0">
            <CardTitle className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Last Sync
            </CardTitle>
            <Clock className="w-4 h-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-lg font-bold">
              {lastSyncUnix > 0 ? formatRelativeTime(lastSyncUnix) : '--'}
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              Interval: every {Math.round(intervalSec / 60)}m
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Domain List Card */}
      <Card className="shadow-xs">
        <CardHeader>
          <CardTitle className="text-base">Configured Domains</CardTitle>
          <CardDescription>
            DNS hostnames managed by lanpilot with provider <span className="font-semibold text-foreground capitalize">{provider}</span>
          </CardDescription>
        </CardHeader>
        <CardContent>
          {domains.length > 0 ? (
            <div className="flex flex-wrap gap-2">
              {domains.map((dom) => (
                <div
                  key={dom}
                  className="flex items-center gap-2 px-3 py-1.5 rounded-lg border bg-muted/30 hover:bg-muted/50 transition-colors font-mono text-sm"
                >
                  <span>{dom}</span>
                  <a
                    href={`https://${dom}`}
                    target="_blank"
                    rel="noreferrer"
                    className="text-muted-foreground hover:text-foreground transition-colors"
                    title={`Open https://${dom}`}
                  >
                    <ExternalLink className="w-3.5 h-3.5" />
                  </a>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-sm text-muted-foreground py-2">
              No domains configured. Set <code className="bg-muted px-1.5 py-0.5 rounded text-xs">DDNS_DOMAINS</code> in your environment or configuration.
            </div>
          )}
        </CardContent>
      </Card>

      {/* Sync History Table */}
      <Card className="shadow-xs">
        <CardHeader>
          <CardTitle className="text-base">Sync History</CardTitle>
          <CardDescription>
            Recent DDNS update attempts and WAN IP changes recorded in SQLite TSDB
          </CardDescription>
        </CardHeader>
        <CardContent>
          {history.length > 0 ? (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[180px]">Timestamp</TableHead>
                    <TableHead className="w-[120px]">Provider</TableHead>
                    <TableHead className="w-[150px]">IPv4</TableHead>
                    <TableHead className="w-[180px]">IPv6</TableHead>
                    <TableHead className="w-[120px]">Status</TableHead>
                    <TableHead>Message / Result</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {history.map((record: any) => {
                    const ts = Number(record.timestampUnix || 0)
                    const isRecSuccess = record.status === 'success'
                    return (
                      <TableRow key={record.id}>
                        <TableCell className="font-mono text-xs whitespace-nowrap">
                          {formatDateTime(ts)}
                        </TableCell>
                        <TableCell className="font-mono text-xs capitalize">
                          {record.provider || '--'}
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          {record.ipv4 || '--'}
                        </TableCell>
                        <TableCell className="font-mono text-xs truncate max-w-[160px]" title={record.ipv6}>
                          {record.ipv6 || '--'}
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant={isRecSuccess ? 'outline' : 'destructive'}
                            className={cn(
                              "text-[11px] py-0 px-1.5 font-normal",
                              isRecSuccess && "border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                            )}
                          >
                            {record.status}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground truncate max-w-[300px]" title={record.message}>
                          {record.message || '--'}
                        </TableCell>
                      </TableRow>
                    )
                  })}
                </TableBody>
              </Table>
            </div>
          ) : (
            <div className="py-8 text-center text-sm text-muted-foreground">
              No DDNS history recorded yet.
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
