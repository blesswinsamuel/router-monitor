import { ArrowLeftRight } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from './ui/card'
import { Badge } from './ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table'
import { cn } from '@/lib/utils'
import { formatBytes, formatPackets } from '@/lib/format'

interface TrafficTabProps {
  flows: any[]
  protocols: any[]
  totalBytes: bigint | number
  totalPackets: bigint | number
}

export function TrafficTab({ flows, protocols, totalBytes, totalPackets }: TrafficTabProps) {
  const totBytesNum = Number(totalBytes || 0)

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {protocols.map((proto, idx) => {
          const bytes = Number(proto.bytes || 0)
          const pct = totBytesNum > 0 ? (bytes / totBytesNum) * 100 : 0
          return (
            <Card key={`${proto.protocol}-${idx}`}>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium flex items-center justify-between">
                  <span>{proto.protocol || 'Other'}</span>
                  <Badge variant="outline" className="text-[11px] font-mono">
                    {pct.toFixed(1)}%
                  </Badge>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-xl font-bold">{formatBytes(proto.bytes)}</div>
                <p className="text-xs text-muted-foreground mt-1">
                  {formatPackets(proto.packets)} packets
                </p>
              </CardContent>
            </Card>
          )
        })}
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <ArrowLeftRight className="w-5 h-5 text-primary" />
                Active Classified Flows (eBPF)
              </CardTitle>
              <CardDescription>
                Flow accounting from TC ingress and egress eBPF maps
              </CardDescription>
            </div>
            <div className="text-xs text-muted-foreground">
              Total Volume: <span className="font-semibold text-foreground">{formatBytes(totalBytes)}</span> ({formatPackets(totalPackets)} pkts)
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Direction</TableHead>
                  <TableHead>Protocol</TableHead>
                  <TableHead>Source IP</TableHead>
                  <TableHead>Destination IP</TableHead>
                  <TableHead className="text-right">Packets</TableHead>
                  <TableHead className="text-right">Volume</TableHead>
                  <TableHead className="text-right">% Share</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {flows.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} className="h-24 text-center text-muted-foreground">
                      No flow data recorded yet.
                    </TableCell>
                  </TableRow>
                ) : (
                  flows.map((flow, idx) => {
                    const isIngress = flow.direction === 'ingress'
                    const b = Number(flow.bytes || 0)
                    const pct = totBytesNum > 0 ? (b / totBytesNum) * 100 : 0

                    return (
                      <TableRow key={`${flow.direction}-${flow.srcIp}-${flow.dstIp}-${idx}`}>
                        <TableCell>
                          <Badge
                            variant={isIngress ? "outline" : "secondary"}
                            className={cn(isIngress && "border-emerald-500/20 bg-emerald-500/15 text-emerald-600 dark:text-emerald-400")}
                          >
                            {flow.direction}
                          </Badge>
                        </TableCell>
                        <TableCell className="font-mono text-xs font-semibold">
                          {flow.ipProto || flow.ethProto || 'IP'}
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          {flow.srcIp === 'internet' ? (
                            <Badge variant="outline" className="text-muted-foreground">internet</Badge>
                          ) : (
                            <span className="font-medium text-foreground">{flow.srcIp}</span>
                          )}
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          {flow.dstIp === 'internet' ? (
                            <Badge variant="outline" className="text-muted-foreground">internet</Badge>
                          ) : (
                            <span className="font-medium text-foreground">{flow.dstIp}</span>
                          )}
                        </TableCell>
                        <TableCell className="text-right font-mono text-xs">
                          {formatPackets(flow.packets)}
                        </TableCell>
                        <TableCell className="text-right font-mono text-xs font-semibold">
                          {formatBytes(flow.bytes)}
                        </TableCell>
                        <TableCell className="text-right font-mono text-xs text-muted-foreground">
                          {pct.toFixed(1)}%
                        </TableCell>
                      </TableRow>
                    )
                  })
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
