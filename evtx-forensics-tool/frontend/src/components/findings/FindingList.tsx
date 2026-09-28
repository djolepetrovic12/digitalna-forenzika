import React from 'react';
import { Finding } from '../../types/finding';

interface FindingListProps {
  findings: Finding[];
}

export function FindingList({ findings }: FindingListProps) {
  return (
    <div>
      {findings.map((finding) => (
        <article key={finding.id}>
          <h3>{finding.title}</h3>
          <p>{finding.summary}</p>
          <p>Confidence: {finding.confidence}</p>
          <p>Correlation: {finding.correlation_type}</p>
          {finding.evidence_event_ids?.length ? (
            <details>
              <summary>Evidence ({finding.evidence_event_ids.length})</summary>
              <ul>
                {finding.evidence_event_ids.map((eventId) => <li key={eventId}>Event {eventId}</li>)}
              </ul>
            </details>
          ) : null}
        </article>
      ))}
    </div>
  );
}
