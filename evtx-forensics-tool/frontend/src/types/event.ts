export type EventCategory =
  | 'AUTHENTICATION'
  | 'SESSION'
  | 'REMOTE_SESSION'
  | 'ACCOUNT_MANAGEMENT'
  | 'GROUP_MEMBERSHIP'
  | 'PRIVILEGE'
  | 'SYSTEM_STARTUP'
  | 'SYSTEM_SHUTDOWN'
  | 'APPLICATION'
  | 'OTHER';

export interface EventRecord {
  id: string;
  source_filename?: string;
  timestamp_utc?: string;
  record_id?: string;
  provider?: string;
  channel?: string;
  event_id?: number;
  version?: number;
  computer?: string;
  level?: string;
  category?: EventCategory;
  title?: string;
  subject_user?: string;
  subject_domain?: string;
  subject_sid?: string;
  target_user?: string;
  target_domain?: string;
  target_sid?: string;
  logon_id?: string;
  logon_type?: number;
  logon_type_name?: string;
  source_ip?: string;
  source_host?: string;
  status?: string;
  sub_status?: string;
  group_name?: string;
  group_sid?: string;
  attributes?: Record<string, unknown>;
  raw_xml?: string;
}
