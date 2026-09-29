import React from 'react';
import { EventDetail } from '../components/events/EventDetail';
import { EventRecord } from '../types/event';
import { Finding } from '../types/finding';

interface FindingsPageProps {
  findings: Finding[];
  events: EventRecord[];
}

export function FindingsPage({ findings, events }: FindingsPageProps) {
  const [selectedFindingId, setSelectedFindingId] = React.useState<string | null>(findings[0]?.id ?? null);
  const [selectedEventId, setSelectedEventId] = React.useState<string | null>(null);
  const [query, setQuery] = React.useState('');
  const selectedFinding = findings.find((finding) => finding.id === selectedFindingId) ?? null;
  const eventsById = new Map(events.map((event) => [event.id, event]));
  const evidenceEvents = (selectedFinding?.evidence_event_ids ?? [])
    .map((eventId) => eventsById.get(eventId))
    .filter((event): event is EventRecord => event !== undefined);
  const selectedEvent = selectedEventId ? eventsById.get(selectedEventId) ?? null : null;
  const filteredFindings = findings.filter((finding) =>
    `${finding.title} ${finding.type} ${finding.summary}`.toLowerCase().includes(query.toLowerCase()),
  );

  return (
    <div className="timeline-layout">
      <section>
        <h1>Findings</h1>
        <input className="search-input" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Filter findings" aria-label="Filter findings" />
        <div className="timeline-list">
          {filteredFindings.map((finding) => (
            <button
              className={`timeline-row ${selectedFinding?.id === finding.id ? 'selected' : ''}`}
              type="button"
              key={finding.id}
              onClick={() => { setSelectedFindingId(finding.id); setSelectedEventId(null); }}
            >
              <span className="timeline-time">{finding.start_time ? new Date(finding.start_time).toLocaleString() : 'Unknown time'}</span>
              <span><strong>{finding.title}</strong><small>{finding.type} · {finding.confidence} confidence · {finding.evidence_event_ids?.length ?? 0} evidence events</small></span>
            </button>
          ))}
        </div>
      </section>
      <aside className="event-detail card">
        {selectedFinding ? (
          <>
            <p className="eyebrow">Finding detail</p>
            <h2>{selectedFinding.title}</h2>
            <p>{selectedFinding.summary}</p>
            <dl className="detail-grid">
              <dt>Type</dt><dd>{selectedFinding.type}</dd>
              <dt>Confidence</dt><dd>{selectedFinding.confidence}</dd>
              <dt>Correlation</dt><dd>{selectedFinding.correlation_type}</dd>
              <dt>Start</dt><dd>{selectedFinding.start_time ?? 'N/A'}</dd>
              <dt>End</dt><dd>{selectedFinding.end_time ?? 'N/A'}</dd>
            </dl>
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
              {evidenceEvents.length === 0 && <p>No linked event records are available for this finding.</p>}
            </div>
            {selectedEvent && <section className="evidence-detail"><EventDetail event={selectedEvent} /></section>}
          </>
        ) : <p>Select a finding to inspect its summary and supporting events.</p>}
      </aside>
    </div>
  );
}
