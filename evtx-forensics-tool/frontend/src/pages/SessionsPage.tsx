import React from 'react';
import { EventDetail } from '../components/events/EventDetail';
import { EventRecord } from '../types/event';
import { SessionRecord } from '../types/session';

interface SessionsPageProps {
  sessions: SessionRecord[];
  events: EventRecord[];
}

export function SessionsPage({ sessions, events }: SessionsPageProps) {
  const [selectedSessionId, setSelectedSessionId] = React.useState<string | null>(sessions[0]?.id ?? null);
  const [selectedEventId, setSelectedEventId] = React.useState<string | null>(null);
  const [query, setQuery] = React.useState('');
  const selectedSession = sessions.find((session) => session.id === selectedSessionId) ?? null;
  const eventsById = new Map(events.map((event) => [event.id, event]));
  const evidenceEvents = (selectedSession?.evidence_event_ids ?? [])
    .map((eventId) => eventsById.get(eventId))
    .filter((event): event is EventRecord => event !== undefined);
  const selectedEvent = selectedEventId ? eventsById.get(selectedEventId) ?? null : null;
  const filteredSessions = sessions.filter((session) =>
    `${session.user ?? ''} ${session.computer ?? ''} ${session.logon_id ?? ''} ${session.status ?? ''}`.toLowerCase().includes(query.toLowerCase()),
  );

  return (
    <div className="timeline-layout">
      <section>
        <h1>Sessions</h1>
        <input className="search-input" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Filter sessions" aria-label="Filter sessions" />
        <div className="timeline-list">
          {filteredSessions.map((session) => (
            <button
              className={`timeline-row ${selectedSession?.id === session.id ? 'selected' : ''}`}
              type="button"
              key={session.id}
              onClick={() => { setSelectedSessionId(session.id); setSelectedEventId(null); }}
            >
              <span className="timeline-time">{session.start_time ? new Date(session.start_time).toLocaleString() : 'Unknown time'}</span>
              <span><strong>{session.user ?? 'Unknown user'} @ {session.computer ?? 'Unknown computer'}</strong><small>Logon {session.logon_id ?? 'N/A'} · {session.status ?? 'unknown'} · {session.evidence_event_ids?.length ?? 0} events</small></span>
            </button>
          ))}
        </div>
      </section>
      <aside className="event-detail card">
        {selectedSession ? (
          <>
            <p className="eyebrow">Session detail</p>
            <h2>{selectedSession.user ?? 'Unknown user'} @ {selectedSession.computer ?? 'Unknown computer'}</h2>
            <dl className="detail-grid">
              <dt>Logon ID</dt><dd>{selectedSession.logon_id ?? 'N/A'}</dd>
              <dt>Logon type</dt><dd>{selectedSession.logon_type ?? 'N/A'}</dd>
              <dt>Start</dt><dd>{selectedSession.start_time ?? 'N/A'}</dd>
              <dt>End</dt><dd>{selectedSession.end_time ?? 'N/A'}</dd>
              <dt>Status</dt><dd>{selectedSession.status ?? 'unknown'}</dd>
            </dl>
            <h3>Correlation notes</h3>
            <ul>{selectedSession.correlation_notes?.map((note) => <li key={note}>{note}</li>)}</ul>
            <h3>Evidence events</h3>
            <div className="timeline-list evidence-list">
              {evidenceEvents.map((event) => (
                <button
                  className={`timeline-row ${selectedEvent?.id === event.id ? 'selected' : ''}`}
                  type="button"
                  key={event.id}
                  onClick={() => setSelectedEventId(event.id)}
                >
                  <span className="timeline-time">{event.timestamp_utc ? new Date(event.timestamp_utc).toLocaleString() : 'Unknown time'}</span>
                  <span><strong>{event.title ?? `Event ${event.event_id ?? 'unknown'}`}</strong><small>{event.source_filename ?? event.channel ?? 'Unknown source'} · Record {event.record_id ?? 'N/A'}</small></span>
                </button>
              ))}
              {evidenceEvents.length === 0 && <p>No linked event records are available for this session.</p>}
            </div>
            {selectedEvent && <section className="evidence-detail"><EventDetail event={selectedEvent} /></section>}
          </>
        ) : <p>Select a session to inspect its details and supporting events.</p>}
      </aside>
    </div>
  );
}
