import { useState, useEffect, useCallback, useMemo } from 'react'
import { Plus, Search, Server, Pencil, Trash2, Globe, RefreshCw } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { EditDnsRecordModal } from '@/components/EditDnsRecordModal'
import { rpcClient } from '@/lib/client'
import type { ConfigDnsRecord } from '@/gen/routermonitor/v1/router_monitor_pb'

export function DnsRecordsPage() {
  const [records, setRecords] = useState<ConfigDnsRecord[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [modalOpen, setModalOpen] = useState(false)
  const [selectedRecord, setSelectedRecord] = useState<ConfigDnsRecord | null>(null)

  const fetchRecords = useCallback(async () => {
    setLoading(true)
    try {
      const res = await rpcClient.listConfigDnsRecords({})
      setRecords(res.records || [])
    } catch (err) {
      console.error('Failed to load DNS records:', err)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchRecords()
  }, [fetchRecords])

  const filtered = useMemo(() => {
    if (!search.trim()) return records
    const q = search.toLowerCase()
    return records.filter(
      (r) =>
        r.name.toLowerCase().includes(q) ||
        r.ip.toLowerCase().includes(q) ||
        r.aliases.some((a) => a.toLowerCase().includes(q))
    )
  }, [records, search])

  const handleEdit = (rec: ConfigDnsRecord) => {
    setSelectedRecord(rec)
    setModalOpen(true)
  }

  const handleAddNew = () => {
    setSelectedRecord(null)
    setModalOpen(true)
  }

  const handleDelete = async (name: string) => {
    if (!window.confirm(`Delete DNS record "${name}"?`)) return
    try {
      await rpcClient.deleteConfigDnsRecord({ name })
      await fetchRecords()
    } catch (err) {
      console.error('Failed to delete DNS record:', err)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold tracking-tight flex items-center gap-2">
            <Server className="w-6 h-6 text-primary" />
            Static DNS Records
          </h2>
          <p className="text-sm text-muted-foreground mt-1">
            Static host records and CNAME/FQDN aliases managed in <code className="bg-muted px-1 rounded text-foreground font-mono">devices.yaml</code>.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={fetchRecords} disabled={loading} className="gap-1.5">
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </Button>
          <Button size="sm" onClick={handleAddNew} className="gap-1.5">
            <Plus className="w-3.5 h-3.5" />
            <span>Add DNS Record</span>
          </Button>
        </div>
      </div>

      <Card>
        <CardHeader className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <CardTitle>DNS Host Entries</CardTitle>
            <CardDescription>
              Custom DNS resolutions written to dnsmasq hosts. Local domain suffix is automatically resolved.
            </CardDescription>
          </div>
          <div className="relative w-full sm:w-72">
            <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search by name, IP, alias..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-8 text-sm"
            />
          </div>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Host Name</TableHead>
                  <TableHead>Target IP Address</TableHead>
                  <TableHead>Aliases / FQDNs</TableHead>
                  <TableHead className="w-24 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={4} className="h-24 text-center text-muted-foreground">
                      {records.length === 0 ? 'No custom DNS records configured.' : 'No DNS records match the search filter.'}
                    </TableCell>
                  </TableRow>
                ) : (
                  filtered.map((rec) => (
                    <TableRow key={rec.name} className="hover:bg-muted/40 transition-colors">
                      <TableCell className="font-semibold text-foreground flex items-center gap-2">
                        <Globe className="w-4 h-4 text-muted-foreground" />
                        <span className="font-mono text-sm">{rec.name}</span>
                      </TableCell>
                      <TableCell className="font-mono text-xs">{rec.ip}</TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-1">
                          {rec.aliases.map((alias) => (
                            <Badge key={alias} variant="secondary" className="font-mono text-[11px] px-1.5 py-0">
                              {alias}
                            </Badge>
                          ))}
                        </div>
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end gap-1">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleEdit(rec)}
                            className="h-8 w-8 p-0"
                            title="Edit Record"
                          >
                            <Pencil className="w-3.5 h-3.5 text-muted-foreground hover:text-foreground" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleDelete(rec.name)}
                            className="h-8 w-8 p-0 hover:text-destructive"
                            title="Delete Record"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      <EditDnsRecordModal
        isOpen={modalOpen}
        onClose={() => setModalOpen(false)}
        record={selectedRecord}
        onSaved={fetchRecords}
      />
    </div>
  )
}
