import { useEffect, useState, useCallback } from 'react'
import { Outlet, NavLink, useOutletContext } from 'react-router-dom'
import { Header } from './Header'
import { rpcClient } from '@/lib/client'
import { cn } from '@/lib/utils'
import { LayoutDashboard, Laptop, Activity } from 'lucide-react'

export interface RootOutletContext {
  overview: any
  devices: any[]
  health: any
  isLive: boolean
  isRefreshing: boolean
  error: string | null
  fetchAllData: () => Promise<void>
}

export function useRootOutletContext() {
  return useOutletContext<RootOutletContext>()
}

export function RootLayout() {
  const [overview, setOverview] = useState<any>(null)
  const [devices, setDevices] = useState<any[]>([])
  const [health, setHealth] = useState<any>(null)
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Fetch all snapshot data (devices, flows, health, overview)
  const fetchAllData = useCallback(async () => {
    setIsRefreshing(true)
    try {
      const [ov, dev, hl] = await Promise.all([
        rpcClient.getOverview({}),
        rpcClient.listDevices({}),
        rpcClient.getInternetHealth({}),
      ])
      setOverview(ov)
      setDevices(dev.devices || [])
      setHealth(hl)
      setError(null)
    } catch (err: any) {
      console.error('Failed to fetch router monitor data:', err)
      setError(err?.message || 'Failed to connect to router monitor service')
    } finally {
      setIsRefreshing(false)
    }
  }, [])

  // Initial load and periodic snapshot refresh every 15s (matching TSDB sample interval)
  useEffect(() => {
    fetchAllData()
    const interval = setInterval(fetchAllData, 15000)
    return () => clearInterval(interval)
  }, [fetchAllData])

  const isConnected = !error && !!overview

  const outletContext: RootOutletContext = {
    overview,
    devices,
    health,
    isLive: isConnected,
    isRefreshing,
    error,
    fetchAllData,
  }

  return (
    <div className="min-h-screen bg-background flex flex-col">
      <Header
        interfaceName={overview?.interfaceName || 'lan'}
        lanSubnet={overview?.lanSubnetCidr || '10.100.0.0/16'}
        isLive={isConnected}
        internetIsUp={overview ? overview.internetIsUp : true}
        internetStatus={overview?.internetStatus}
        onRefresh={fetchAllData}
        isRefreshing={isRefreshing}
      />

      <main className="container mx-auto px-4 py-6 flex-1 flex flex-col">
        {/* Navigation Bar */}
        <nav className="flex items-center gap-1 p-1 bg-muted/80 rounded-lg w-fit mb-6 overflow-x-auto">
          <NavLink
            to="/overview"
            className={({ isActive }) =>
              cn(
                "flex items-center gap-2 px-3.5 py-1.5 text-sm font-medium rounded-md transition-all whitespace-nowrap",
                isActive
                  ? "bg-background text-foreground shadow-xs font-semibold"
                  : "text-muted-foreground hover:text-foreground hover:bg-background/50"
              )
            }
          >
            <LayoutDashboard className="w-4 h-4" />
            <span>Overview</span>
          </NavLink>
          <NavLink
            to="/devices"
            className={({ isActive }) =>
              cn(
                "flex items-center gap-2 px-3.5 py-1.5 text-sm font-medium rounded-md transition-all whitespace-nowrap",
                isActive
                  ? "bg-background text-foreground shadow-xs font-semibold"
                  : "text-muted-foreground hover:text-foreground hover:bg-background/50"
              )
            }
          >
            <Laptop className="w-4 h-4" />
            <span>Devices</span>
            {devices.length > 0 && (
              <span className="font-mono text-xs px-1.5 py-0.2 rounded-full bg-muted-foreground/15">
                {devices.length}
              </span>
            )}
          </NavLink>
          <NavLink
            to="/health"
            className={({ isActive }) =>
              cn(
                "flex items-center gap-2 px-3.5 py-1.5 text-sm font-medium rounded-md transition-all whitespace-nowrap",
                isActive
                  ? "bg-background text-foreground shadow-xs font-semibold"
                  : "text-muted-foreground hover:text-foreground hover:bg-background/50"
              )
            }
          >
            <Activity className="w-4 h-4" />
            <span>Health</span>
          </NavLink>
        </nav>

        {error && (
          <div className="mb-6 p-4 rounded-lg bg-destructive/10 border border-destructive/20 text-destructive text-sm flex items-center justify-between">
            <span>Connection error: {error}. Check if router-monitor is running on the router.</span>
            <button
              onClick={fetchAllData}
              className="underline font-semibold hover:opacity-80 ml-4 cursor-pointer"
            >
              Retry
            </button>
          </div>
        )}

        <div className="flex-1 flex flex-col">
          <Outlet context={outletContext} />
        </div>
      </main>

      <footer className="border-t py-4 text-center text-xs text-muted-foreground">
        Router Monitor &copy; <span className="font-mono">{new Date().getFullYear()}</span> • Connect-RPC over gRPC-Web • Pure-Go SQLite TSDB
      </footer>
    </div>
  )
}
