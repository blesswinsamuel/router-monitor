import { useState } from 'react'
import { Search, Laptop, ArrowDown, ArrowUp } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from './ui/card'
import { Input } from './ui/input'
import { Badge } from './ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table'
import { cn } from '@/lib/utils'
import { formatBytes, formatPackets } from '@/lib/format'

interface DevicesTabProps {
  devices: any[]
}

export function DevicesTab({ devices }: DevicesTabProps) {
  const [search, setSearch] = useState('')

  const filtered = devices.filter((d) => {
    const q = search.toLowerCase()
    return (
      d.hostname?.toLowerCase().includes(q) ||
      d.ipAddr?.toLowerCase().includes(q) ||
      d.hwAddr?.toLowerCase().includes(q) ||
      d.device?.toLowerCase().includes(q)
    )
  })

  const totalDl = devices.reduce((acc, d) => acc + Number(d.downloadBytes || 0), 0)
  const totalUl = devices.reduce((acc, d) => acc + Number(d.uploadBytes || 0), 0)

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Laptop className="w-5 h-5 text-primary" />
              Connected Devices
            </CardTitle>
            <CardDescription>
              Discovered from router ARP table with reverse DNS hostnames
            </CardDescription>
          </div>
          <div className="relative w-full sm:w-72">
            <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Filter by IP, MAC, Hostname..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-8 text-sm"
            />
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Hostname / Name</TableHead>
                <TableHead>IP Address</TableHead>
                <TableHead>MAC Address</TableHead>
                <TableHead>Interface</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">
                  <span className="inline-flex items-center gap-1">
                    <ArrowDown className="w-3.5 h-3.5 text-emerald-500" /> Download
                  </span>
                </TableHead>
                <TableHead className="text-right">
                  <span className="inline-flex items-center gap-1">
                    <ArrowUp className="w-3.5 h-3.5 text-sky-500" /> Upload
                  </span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="h-24 text-center text-muted-foreground">
                    {devices.length === 0 ? "No ARP devices detected yet." : "No devices matching search filter."}
                  </TableCell>
                </TableRow>
              ) : (
                filtered.map((device, idx) => {
                  const dl = Number(device.downloadBytes || 0)
                  const dlPct = totalDl > 0 ? (dl / totalDl) * 100 : 0

                  return (
                    <TableRow key={`${device.ipAddr}-${idx}`}>
                      <TableCell className="font-medium">
                        <div className="flex flex-col">
                          <span className="font-semibold text-foreground">
                            {device.hostname && !device.hostname.startsWith('unknown:')
                              ? device.hostname
                              : 'Unknown Device'}
                          </span>
                          <span className="text-xs text-muted-foreground font-mono">
                            {device.ipAddr}
                          </span>
                        </div>
                      </TableCell>
                      <TableCell className="font-mono text-xs">{device.ipAddr}</TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">{device.hwAddr}</TableCell>
                      <TableCell className="font-mono text-xs">
                        <Badge variant="outline">{device.device || 'lan'}</Badge>
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant={device.isValid ? "outline" : "secondary"}
                          className={cn("text-[11px]", device.isValid && "border-emerald-500/20 bg-emerald-500/15 text-emerald-600 dark:text-emerald-400")}
                        >
                          {device.isValid ? "Active" : `Flags: ${device.flags}`}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right font-mono">
                        <div className="flex flex-col items-end">
                          <span className="text-emerald-500 font-semibold">{formatBytes(device.downloadBytes)}</span>
                          <span className="text-[10px] text-muted-foreground">
                            {formatPackets(device.downloadPackets)} pkts ({dlPct.toFixed(1)}%)
                          </span>
                        </div>
                      </TableCell>
                      <TableCell className="text-right font-mono">
                        <div className="flex flex-col items-end">
                          <span className="text-sky-500 font-semibold">{formatBytes(device.uploadBytes)}</span>
                          <span className="text-[10px] text-muted-foreground">
                            {formatPackets(device.uploadPackets)} pkts
                          </span>
                        </div>
                      </TableCell>
                    </TableRow>
                  )
                })
              )}
            </TableBody>
          </Table>
        </div>
        <div className="mt-4 flex items-center justify-between text-xs text-muted-foreground px-1">
          <span>Total Devices: {devices.length}</span>
          <span>
            Total Volume: <span className="font-semibold text-foreground">{formatBytes(totalDl + totalUl)}</span>
          </span>
        </div>
      </CardContent>
    </Card>
  )
}
