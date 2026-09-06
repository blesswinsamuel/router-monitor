import { Link } from 'react-router-dom'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { FileQuestion, ArrowLeft } from 'lucide-react'

export function NotFoundPage() {
  return (
    <div className="flex-1 flex items-center justify-center py-12">
      <Card className="max-w-md w-full text-center border-dashed">
        <CardContent className="pt-8 pb-8 space-y-4">
          <div className="mx-auto w-12 h-12 rounded-full bg-muted flex items-center justify-center text-muted-foreground">
            <FileQuestion className="w-6 h-6" />
          </div>
          <div className="space-y-1">
            <h2 className="text-xl font-bold tracking-tight">404 - Page Not Found</h2>
            <p className="text-sm text-muted-foreground">
              The page you are looking for doesn't exist or has been moved.
            </p>
          </div>
          <div className="pt-2">
            <Button asChild variant="default" size="sm">
              <Link to="/overview" className="flex items-center gap-2">
                <ArrowLeft className="w-4 h-4" />
                <span>Return to Overview</span>
              </Link>
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
