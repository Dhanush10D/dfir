import { useMutation } from '@tanstack/react-query'

import { api } from '@/api/endpoints'
import { Button, ErrorMessage } from '@/components/ui'

import { AiResultCard } from './AiResultCard'

/** "Explain with AI" on an alert (A2). The explanation never changes the alert's status. */
export function AlertAiPanel({ alertId }: { alertId: string }) {
  const call = useMutation({ mutationFn: () => api.aiExplainAlert(alertId) })
  return (
    <section aria-label="AI explanation" className="space-y-2">
      <Button onClick={() => call.mutate()} disabled={call.isPending}>
        {call.isPending ? 'Explaining…' : 'Explain with AI'}
      </Button>
      <ErrorMessage error={call.error} />
      {call.data && <AiResultCard key={call.data.interaction.id} view={call.data} />}
    </section>
  )
}
