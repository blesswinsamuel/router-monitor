import React from 'react'
import { Activity, Moon, Sun, RefreshCw, Radio, Server } from 'lucide-react'
import { Button } from './ui/button'
import { Badge } from './ui/badge'
import { cn } from '@/lib/utils'

interface HeaderProps {
  interfaceName: string
  lanSubnet: string
  isLive: boolean
  internetIsUp: boolean
  onRefresh: () => void
  isRefreshing: boolean
}

export function Header({
  interfaceName,
  lanSubnet,
  isLive,
  internetIsUp,
  onRefresh,
  isRefreshing,
}: HeaderProps) {
  const [isDark, setIsDark] = React.useState(true)

  const toggleTheme = () => {
    const root = document.documentElement
    if (isDark) {
      root.classList.remove('dark')
      setIsDark(false)
    } else {
      root.classList.add('dark')
      setIsDark(true)
    }
  }

  return (
    <header className="border-b bg-card/60 backdrop-blur sticky top-0 z-50">
      <div className="container mx-auto px-4 h-16 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-primary/10 flex items-center justify-center text-primary">
            <Activity className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="font-bold text-lg leading-none">Router Monitor</h1>
              {isLive ? (
                <Badge variant="outline" className="flex items-center gap-1 text-[11px] py-0 px-2 border-emerald-500/20 bg-emerald-500/15 text-emerald-600 dark:text-emerald-400">
                  <span className="relative flex h-2 w-2">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                  </span>
                  Live gRPC-Web
                </Badge>
              ) : (
                <Badge variant="secondary" className="text-[11px] py-0 px-2">Polling</Badge>
              )}
            </div>
            <div className="flex items-center space-x-2 mt-1 text-xs text-muted-foreground">
              <span className="flex items-center gap-1 font-mono">
                <Server className="w-3 h-3" /> {interfaceName || 'lan'}
              </span>
              <span>•</span>
              <span className="font-mono">{lanSubnet || '10.100.0.0/16'}</span>
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <Badge
            variant={internetIsUp ? "outline" : "destructive"}
            className={cn("gap-1 hidden sm:flex", internetIsUp && "border-emerald-500/20 bg-emerald-500/15 text-emerald-600 dark:text-emerald-400")}
          >
            <Radio className="w-3 h-3" />
            {internetIsUp ? "Internet Online" : "Internet Offline"}
          </Badge>

          <Button
            variant="outline"
            size="icon"
            onClick={onRefresh}
            disabled={isRefreshing}
            title="Refresh metrics"
          >
            <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin' : ''}`} />
          </Button>

          <Button
            variant="outline"
            size="icon"
            onClick={toggleTheme}
            title="Toggle theme"
          >
            {isDark ? <Sun className="w-4 h-4 text-amber-400" /> : <Moon className="w-4 h-4" />}
          </Button>
        </div>
      </div>
    </header>
  )
}
