import { useQuery } from '@tanstack/react-query'

import { apiGet } from './client'

export interface HealthResponse {
  status: 'ok'
  service: string
  version: string
  env: string
  time: string
}

export function fetchHealth(signal?: AbortSignal): Promise<HealthResponse> {
  return apiGet<HealthResponse>('/health', { signal })
}

export function useHealth() {
  return useQuery({
    queryKey: ['health'],
    queryFn: ({ signal }) => fetchHealth(signal),
    refetchInterval: 30_000,
  })
}
