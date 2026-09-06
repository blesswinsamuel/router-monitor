import { InternetHealthTab } from '@/components/InternetHealthTab'
import { useRootOutletContext } from '@/components/RootLayout'

export function InternetHealthPage() {
  const { health } = useRootOutletContext()

  return <InternetHealthTab health={health} />
}
