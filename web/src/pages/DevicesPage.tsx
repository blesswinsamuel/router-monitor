import { DevicesTab } from '@/components/DevicesTab'
import { useRootOutletContext } from '@/components/RootLayout'

export function DevicesPage() {
  const { devices } = useRootOutletContext()

  return <DevicesTab devices={devices} />
}
