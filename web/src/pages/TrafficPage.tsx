import { TrafficTab } from '@/components/TrafficTab'
import { useRootOutletContext } from '@/components/RootLayout'

export function TrafficPage() {
  const { trafficData } = useRootOutletContext()

  return (
    <TrafficTab
      flows={trafficData.flows}
      protocols={trafficData.protocols}
      totalBytes={trafficData.totalBytes}
      totalPackets={trafficData.totalPackets}
    />
  )
}
