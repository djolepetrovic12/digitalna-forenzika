import React from 'react';
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
        {selectedEvent ? (
          <>
            <p className="eyebrow">Event detail</p>
            <h2>{selectedEvent.title ?? 'Unknown event'}</h2>
            <dl className="detail-grid">
              <dt>Event ID</dt><dd>{selectedEvent.event_id ?? 'N/A'}</dd>
              <dt>Record ID</dt><dd>{selectedEvent.record_id ?? 'N/A'}</dd>
              <dt>Timestamp</dt><dd>{selectedEvent.timestamp_utc ?? 'N/A'}</dd>
              <dt>Provider</dt><dd>{selectedEvent.provider ?? 'N/A'}</dd>
              <dt>Channel</dt><dd>{selectedEvent.channel ?? 'N/A'}</dd>
              <dt>Computer</dt><dd>{selectedEvent.computer ?? 'N/A'}</dd>
            </dl>
            <h3>Extracted attributes</h3>
            <pre className="code-block">{JSON.stringify(selectedEvent.attributes ?? {}, null, 2)}</pre>
            <h3>Raw XML</h3>
            <pre className="code-block raw-xml">{selectedEvent.raw_xml ?? 'No raw XML available'}</pre>
          </>
        ) : <p>Select an event to inspect its normalized fields and raw XML.</p>}
      </aside>
    </div>
  );
}
