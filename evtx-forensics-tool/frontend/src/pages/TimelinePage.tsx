import React from 'react';
import { EventDetail } from '../components/events/EventDetail';
import { EventRecord } from '../types/event';

interface TimelinePageProps { events: EventRecord[] }

export function TimelinePage({ events }: TimelinePageProps) {
  const [selectedEvent, setSelectedEvent] = React.useState<EventRecord | null>(events[0] ?? null);
  const [query, setQuery] = React.useState('');

  const filteredEvents = events.filter((event) => {
    const haystack = `${event.event_id ?? ''} ${event.title ?? ''} ${event.provider ?? ''} ${event.computer ?? ''} ${event.target_user ?? ''}`.toLowerCase();
    return haystack.includes(query.toLowerCase());
  });

  return (
    <div className="timeline-layout">
      <section>
      <h1>Unified timeline</h1>
      <input className="search-input" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Filter events" aria-label="Filter events" />
      <div className="timeline-list">
        {filteredEvents.map((event) => (
          <button className={`timeline-row ${selectedEvent?.id === event.id ? 'selected' : ''}`} type="button" key={event.id} onClick={() => setSelectedEvent(event)}>
            <span className="timeline-time">{event.timestamp_utc ? new Date(event.timestamp_utc).toLocaleString() : 'Unknown time'}</span>
            <span><strong>{event.title ?? 'Unknown event'}</strong><small>{event.source_filename ?? event.channel ?? 'Unknown source'} · Event {event.event_id ?? 'N/A'} · Record {event.record_id ?? 'N/A'}</small></span>
          </button>
        ))}
      </div>
      </section>
      <aside className="event-detail card">
        <EventDetail event={selectedEvent} />
      </aside>
    </div>
  );
}
