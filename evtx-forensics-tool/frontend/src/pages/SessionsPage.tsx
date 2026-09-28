import { SessionList } from '../components/sessions/SessionList';
import { SessionRecord } from '../types/session';

interface SessionsPageProps { sessions: SessionRecord[] }

export function SessionsPage({ sessions }: SessionsPageProps) {
  return <SessionList sessions={sessions} />;
}
