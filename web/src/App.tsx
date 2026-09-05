import { useEffect, useState, useCallback } from 'react'
import { Header } from './components/Header'
import { OverviewTab, LivePoint } from './components/OverviewTab'
import { DevicesTab } from './components/DevicesTab'
import { TrafficTab } from './components/TrafficTab'
import { InternetHealthTab } from './components/InternetHealthTab'
import { Tabs, TabsContent, TabsList, TabsTrigger } from './components/ui/tabs'
import { rpcClient } from './lib/client'
import { LayoutDashboard, Laptop, ArrowLeftRight, Activity } from 'lucide-react'

export function App() {
  const [overview, setOverview] = useState<any>(null)
  const [devices, setDevices] = useState<any[]>([])
  const [trafficData, setTrafficData] = useState<{ flows: any[]; protocols: any[]; totalBytes: bigint | number; totalPackets: bigint | number }>({
    flows: [],
    protocols: [],
    totalBytes: 0,
    totalPackets: 0,
  })
  const [health, setHealth] = useState<any>(null)
  const [liveHistory, setLiveHistory] = useState<LivePoint[]>([])
  const [isLive, setIsLive] = useState(false)
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Fetch all snapshot data (devices, flows, health, overview)
  const fetchAllData = useCallback(async () => {
    setIsRefreshing(true)
    try {
      const [ov, dev, tr, hl] = await Promise.all([
        rpcClient.getOverview({}),
        rpcClient.listDevices({}),
        rpcClient.getTrafficFlows({ limit: 100 }),
        rpcClient.getInternetHealth({}),
      ])
      setOverview(ov)
      setDevices(dev.devices || [])
      setTrafficData({
        flows: tr.flows || [],
        protocols: tr.protocols || [],
        totalBytes: tr.totalBytes,
        totalPackets: tr.totalPackets,
      })
      setHealth(hl)
      setError(null)
    } catch (err: any) {
      console.error('Failed to fetch router monitor data:', err)
      setError(err?.message || 'Failed to connect to router monitor service')
    } finally {
      setIsRefreshing(false)
    }
  }, [])

  // Initial load and periodic snapshot refresh
  useEffect(() => {
    fetchAllData()
    const interval = setInterval(fetchAllData, 10000)
    return () => clearInterval(interval)
  }, [fetchAllData])

  // Server-streaming gRPC-Web connection for 1-second live stats
  useEffect(() => {
    let active = true
    const abortCtrl = new AbortController()

    async function runStream() {
      while (active) {
        try {
          const stream = rpcClient.streamLiveStats(
            { intervalSeconds: 1 },
            { signal: abortCtrl.signal }
          )
          setIsLive(true)

          for await (const res of stream) {
            if (!active) break
            setIsLive(true)

            // Update live rates on overview
            setOverview((prev: any) => ({
              ...prev,
              currentDownloadBytesPerSec: res.downloadBytesPerSec,
              currentUploadBytesPerSec: res.uploadBytesPerSec,
              currentDownloadPacketsPerSec: res.downloadPacketsPerSec,
              currentUploadPacketsPerSec: res.uploadPacketsPerSec,
              internetIsUp: res.internetIsUp,
              internetLatencySeconds: res.internetLatencySeconds,
              connectedDevicesCount: res.connectedDevicesCount,
            }))

            // Append to rolling 60-second live chart
            const d = new Date(Number(res.timestampUnix) * 1000)
            const timeStr = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })

            setLiveHistory((prev) => {
              const next = [...prev, { time: timeStr, download: res.downloadBytesPerSec, upload: res.uploadBytesPerSec }]
              if (next.length > 60) return next.slice(next.length - 60)
              return next
            })
          }
        } catch (err: any) {
          if (!active) break
          setIsLive(false)
          // Wait 3 seconds before reconnecting stream
          await new Promise((r) => setTimeout(r, 3000))
        }
      }
    }

    runStream()

    return () => {
      active = false
      abortCtrl.abort()
    }
  }, [])

  return (
    <div className="min-h-screen bg-background flex flex-col">
      <Header
        interfaceName={overview?.interfaceName || 'lan'}
        lanSubnet={overview?.lanSubnetCidr || '10.100.0.0/16'}
        isLive={isLive}
        internetIsUp={overview ? overview.internetIsUp : true}
        onRefresh={fetchAllData}
        isRefreshing={isRefreshing}
      />

      <main className="container mx-auto px-4 py-6 flex-1">
        {error && (
          <div className="mb-6 p-4 rounded-lg bg-destructive/10 border border-destructive/20 text-destructive text-sm flex items-center justify-between">
            <span>Connection error: {error}. Check if router-monitor is running on the router.</span>
            <button
              onClick={fetchAllData}
              className="underline font-semibold hover:opacity-80 ml-4"
            >
              Retry
            </button>
          </div>
        )}

        <Tabs defaultValue="overview" className="space-y-6">
          <TabsList className="grid grid-cols-4 w-full max-w-lg">
            <TabsTrigger value="overview" className="flex items-center gap-2">
              <LayoutDashboard className="w-4 h-4" />
              <span>Overview</span>
            </TabsTrigger>
            <TabsTrigger value="devices" className="flex items-center gap-2">
              <Laptop className="w-4 h-4" />
              <span>Devices ({devices.length})</span>
            </TabsTrigger>
            <TabsTrigger value="traffic" className="flex items-center gap-2">
              <ArrowLeftRight className="w-4 h-4" />
              <span>Traffic</span>
            </TabsTrigger>
            <TabsTrigger value="health" className="flex items-center gap-2">
              <Activity className="w-4 h-4" />
              <span>Health</span>
            </TabsTrigger>
          </TabsList>

          <TabsContent value="overview">
            <OverviewTab overview={overview} liveHistory={liveHistory} />
          </TabsContent>

          <TabsContent value="devices">
            <DevicesTab devices={devices} />
          </TabsContent>

          <TabsContent value="traffic">
            <TrafficTab
              flows={trafficData.flows}
              protocols={trafficData.protocols}
              totalBytes={trafficData.totalBytes}
              totalPackets={trafficData.totalPackets}
            />
          </TabsContent>

          <TabsContent value="health">
            <InternetHealthTab health={health} />
          </TabsContent>
        </Tabs>
      </main>

      <footer className="border-t py-4 text-center text-xs text-muted-foreground">
        Router Monitor &copy; {new Date().getFullYear()} • Connect-RPC over gRPC-Web • Pure-Go SQLite TSDB
      </footer>
    </div>
  )
}
