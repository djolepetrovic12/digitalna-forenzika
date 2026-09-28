import React from 'react';
import { SessionRecord } from '../../types/session';

interface SessionListProps {
  sessions: SessionRecord[];
}

export function SessionList({ sessions }: SessionListProps) {
  return (
    <div>
      {sessions.map((session) => (
        <div key={session.id}>
          <h3>{session.user} @ {session.computer}</h3>
          <p>Logon ID: {session.logon_id ?? 'N/A'}</p>
          <p>Start: {session.start_time ?? 'N/A'}</p>
          <p>End: {session.end_time ?? 'N/A'}</p>
          <p>Status: {session.status ?? 'unknown'}</p>
        </div>
      ))}
    </div>
  );
}
