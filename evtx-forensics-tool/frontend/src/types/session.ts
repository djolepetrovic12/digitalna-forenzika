export interface SessionRecord {
  id: string;
  user?: string;
  computer?: string;
  logon_id?: string;
  logon_type?: number;
  start_time?: string;
  end_time?: string;
  evidence_event_ids?: string[];
  correlation_notes?: string[];
  status?: string;
}
