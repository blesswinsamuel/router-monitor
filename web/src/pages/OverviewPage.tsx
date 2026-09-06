import { OverviewTab } from '@/components/OverviewTab'
import { useRootOutletContext } from '@/components/RootLayout'

export function OverviewPage() {
  const { overview } = useRootOutletContext()

  return <OverviewTab overview={overview} />
}
