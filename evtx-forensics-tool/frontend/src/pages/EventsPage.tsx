import { EventTable } from '../components/events/EventTable';
import { EventRecord } from '../types/event';

interface EventsPageProps { events: EventRecord[] }

export function EventsPage({ events }: EventsPageProps) {
  return <EventTable events={events} />;
}
