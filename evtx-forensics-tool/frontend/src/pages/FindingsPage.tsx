import { FindingList } from '../components/findings/FindingList';
import { Finding } from '../types/finding';

interface FindingsPageProps { findings: Finding[] }

export function FindingsPage({ findings }: FindingsPageProps) {
  return <FindingList findings={findings} />;
}
