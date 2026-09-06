import { useState, useMemo } from 'react'
import { Search, Laptop, ArrowDown, ArrowUp, Network } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from './ui/card'
import { Input } from './ui/input'
import { Badge } from './ui/badge'
import { Tabs, TabsList, TabsTrigger } from './ui/tabs'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table'
import { cn } from '@/lib/utils'
import { formatBytes, formatPackets } from '@/lib/format'

interface DevicesTabProps {
  devices: any[]
}

export function DevicesTab({ devices }: DevicesTabProps) {
  const [search, setSearch] = useState('')
  const [selectedInterface, setSelectedInterface] = useState<string>('all')

  // Extract unique interface names
  const interfaces = useMemo(() => {
    const set = new Set<string>()
    for (const d of devices) {
      set.add(d.device || 'lan')
    }
    return Array.from(set).sort()
  }, [devices])

  // Count devices per interface
  const interfaceCounts = useMemo(() => {
    const counts: Record<string, number> = {}
    for (const d of devices) {
      const iface = d.device || 'lan'
      counts[iface] = (counts[iface] || 0) + 1
    }
    return counts
  }, [devices])

  // Fallback to 'all' if selected interface is no longer present
  const currentInterface =
    selectedInterface === 'all' || interfaces.includes(selectedInterface)
      ? selectedInterface
      : 'all'

  const filtered = useMemo(() => {
    return devices.filter((d) => {
      const iface = d.device || 'lan'
      if (currentInterface !== 'all' && iface !== currentInterface) {
        return false
      }
      if (!search.trim()) return true
      const q = search.toLowerCase()
      return (
        d.hostname?.toLowerCase().includes(q) ||
        d.ipAddr?.toLowerCase().includes(q) ||
        d.hwAddr?.toLowerCase().includes(q) ||
        d.device?.toLowerCase().includes(q)
      )
    })
  }, [devices, currentInterface, search])

  const totalDl = devices.reduce((acc, d) => acc + Number(d.downloadBytes || 0), 0)
  const totalUl = devices.reduce((acc, d) => acc + Number(d.uploadBytes || 0), 0)

  const filteredDl = filtered.reduce((acc, d) => acc + Number(d.downloadBytes || 0), 0)
  const filteredUl = filtered.reduce((acc, d) => acc + Number(d.uploadBytes || 0), 0)

  return (
    <Card>
      <CardHeader className="space-y-4">
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

        {interfaces.length > 1 && (
          <div className="flex items-center gap-2 pt-2 border-t overflow-x-auto pb-0.5">
            <div className="text-xs font-medium text-muted-foreground flex items-center gap-1.5 shrink-0 mr-1">
              <Network className="w-3.5 h-3.5" />
              <span>Interface:</span>
            </div>
            <Tabs value={currentInterface} onValueChange={setSelectedInterface} className="shrink-0">
              <TabsList className="h-8">
                <TabsTrigger value="all" className="text-xs px-2.5 py-1 flex items-center gap-1.5">
                  <span>All</span>
                  <span
                    className={cn(
                      "px-1.5 py-0.2 rounded-full text-[10px] font-mono",
                      currentInterface === 'all'
                        ? "bg-primary/15 text-primary font-semibold"
                        : "bg-muted-foreground/15 text-muted-foreground"
                    )}
                  >
                    {devices.length}
                  </span>
                </TabsTrigger>
                {interfaces.map((iface) => (
                  <TabsTrigger
                    key={iface}
                    value={iface}
                    className="text-xs px-2.5 py-1 flex items-center gap-1.5"
                  >
                    <span>{iface}</span>
                    <span
                      className={cn(
                        "px-1.5 py-0.2 rounded-full text-[10px] font-mono",
                        currentInterface === iface
                          ? "bg-primary/15 text-primary font-semibold"
                          : "bg-muted-foreground/15 text-muted-foreground"
                      )}
                    >
                      {interfaceCounts[iface] || 0}
                    </span>
                  </TabsTrigger>
                ))}
              </TabsList>
            </Tabs>
          </div>
        )}
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
                    {devices.length === 0
                      ? "No ARP devices detected yet."
                      : currentInterface !== 'all' && !search
                        ? `No devices detected on interface "${currentInterface}".`
                        : "No devices matching search filter."}
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
        <div className="mt-4 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs text-muted-foreground px-1">
          <span>
            Showing {filtered.length} of {devices.length} {devices.length === 1 ? 'device' : 'devices'}
            {currentInterface !== 'all' && ` (interface: ${currentInterface})`}
          </span>
          <span>
            {currentInterface !== 'all' ? (
              <>
                {currentInterface} Volume: <span className="font-semibold text-foreground">{formatBytes(filteredDl + filteredUl)}</span>
                <span className="ml-1">({formatBytes(totalDl + totalUl)} total)</span>
              </>
            ) : (
              <>
                Total Volume: <span className="font-semibold text-foreground">{formatBytes(totalDl + totalUl)}</span>
              </>
            )}
          </span>
        </div>
      </CardContent>
    </Card>
  )
}
