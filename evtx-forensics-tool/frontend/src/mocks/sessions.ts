import { SessionRecord } from '../types/session';

export const mockSessions: SessionRecord[] = [
  {
    id: 'session-1',
    user: 'alice',
    computer: 'WIN-TEST',
    logon_id: '0x100',
    logon_type: 2,
    start_time: '2026-09-20T10:00:00Z',
    end_time: '2026-09-20T10:15:00Z',
    evidence_event_ids: ['evt-1', 'evt-2', 'evt-3'],
    correlation_notes: ['matched by computer + Logon ID', 'supports logon session reconstruction'],
    status: 'closed',
  },
];
