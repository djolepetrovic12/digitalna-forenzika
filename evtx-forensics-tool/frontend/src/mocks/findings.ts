import { Finding } from '../types/finding';

export const mockFindings: Finding[] = [
  {
    id: 'finding-1',
    type: 'SESSION',
    title: 'Successful logon session',
    summary: 'A logon session for alice was reconstructed from supported security events.',
    start_time: '2026-09-20T10:00:00Z',
    end_time: '2026-09-20T10:15:00Z',
    correlation_type: 'direct',
    confidence: 'HIGH',
    metadata: {
      reason: ['matched computer + Logon ID', 'supported 4624 -> 4672 -> 4647 flow'],
      event_ids: ['evt-1', 'evt-2', 'evt-3'],
    },
  },
];
