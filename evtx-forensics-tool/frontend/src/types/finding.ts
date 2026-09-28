export type CorrelationConfidence = 'HIGH' | 'MEDIUM' | 'LOW';
export type CorrelationType = 'direct' | 'indirect';

export interface Finding {
  id: string;
  type: string;
  title: string;
  summary: string;
  start_time?: string;
  end_time?: string;
  correlation_type: CorrelationType;
  confidence: CorrelationConfidence;
  metadata?: Record<string, unknown>;
  evidence_event_ids?: string[];
}
