import { OverviewTab } from '@/components/OverviewTab'
import { useRootOutletContext } from '@/components/RootLayout'

export function OverviewPage() {
  const { overview, liveHistory } = useRootOutletContext()

  return <OverviewTab overview={overview} liveHistory={liveHistory} />
}
