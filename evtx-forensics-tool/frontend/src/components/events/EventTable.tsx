import React from 'react';
import { EventRecord } from '../../types/event';

interface EventTableProps {
  events: EventRecord[];
}

export function EventTable({ events }: EventTableProps) {
  return (
    <table>
      <thead>
        <tr>
          <th>Timestamp</th>
          <th>Event ID</th>
          <th>Channel</th>
          <th>Computer</th>
          <th>User</th>
          <th>Source IP</th>
        </tr>
      </thead>
      <tbody>
        {events.map((event) => (
          <tr key={event.id}>
            <td>{event.timestamp_utc ?? 'N/A'}</td>
            <td>{event.event_id ?? 'N/A'}</td>
            <td>{event.channel ?? 'N/A'}</td>
            <td>{event.computer ?? 'N/A'}</td>
            <td>{event.target_user ?? event.subject_user ?? 'N/A'}</td>
            <td>{event.source_ip ?? 'N/A'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
