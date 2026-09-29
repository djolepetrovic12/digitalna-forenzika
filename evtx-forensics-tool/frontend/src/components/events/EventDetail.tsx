import { EventRecord } from '../../types/event';

interface EventDetailProps {
  event: EventRecord | null;
}

export function EventDetail({ event }: EventDetailProps) {
  if (!event) return <p>Select an event to inspect its normalized fields and raw XML.</p>;

  return (
    <>
      <p className="eyebrow">Event detail</p>
      <h2>{event.title ?? 'Unknown event'}</h2>
      <dl className="detail-grid">
        <dt>Event ID</dt><dd>{event.event_id ?? 'N/A'}</dd>
        <dt>Record ID</dt><dd>{event.record_id ?? 'N/A'}</dd>
        <dt>Timestamp</dt><dd>{event.timestamp_utc ?? 'N/A'}</dd>
        <dt>Provider</dt><dd>{event.provider ?? 'N/A'}</dd>
        <dt>Channel</dt><dd>{event.channel ?? 'N/A'}</dd>
        <dt>Computer</dt><dd>{event.computer ?? 'N/A'}</dd>
        <dt>Source file</dt><dd>{event.source_filename ?? 'N/A'}</dd>
        <dt>User</dt><dd>{event.target_user ?? event.subject_user ?? 'N/A'}</dd>
        <dt>Source IP</dt><dd>{event.source_ip ?? 'N/A'}</dd>
      </dl>
      <h3>Extracted attributes</h3>
      <pre className="code-block">{JSON.stringify(event.attributes ?? {}, null, 2)}</pre>
      <h3>Raw XML</h3>
      <pre className="code-block raw-xml">{event.raw_xml ?? 'No raw XML available'}</pre>
    </>
  );
}