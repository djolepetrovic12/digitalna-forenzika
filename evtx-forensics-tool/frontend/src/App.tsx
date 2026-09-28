import React from 'react';
import { EvtxAnalysisReport } from './api/analysis';
import { EventsPage } from './pages/EventsPage';
import { FindingsPage } from './pages/FindingsPage';
import { OverviewPage } from './pages/OverviewPage';
import { SessionsPage } from './pages/SessionsPage';
import { ImportPage } from './pages/ImportPage';
import { TimelinePage } from './pages/TimelinePage';

type View = 'overview' | 'events' | 'timeline' | 'findings' | 'sessions' | 'import';

const navigation: Array<{ id: View; label: string }> = [
  { id: 'overview', label: 'Overview' },
  { id: 'events', label: 'Events' },
  { id: 'timeline', label: 'Timeline' },
  { id: 'findings', label: 'Findings' },
  { id: 'sessions', label: 'Sessions' },
  { id: 'import', label: 'Import EVTX' },
];

export function App() {
  const [view, setView] = React.useState<View>('overview');
  const [report, setReport] = React.useState<EvtxAnalysisReport | null>(null);

  return (
    <main className="app">
      <header className="header">
        <div>
          <p className="eyebrow">In-memory EVTX analysis</p>
          <h1>Windows Event Log Analyzer</h1>
        </div>
      </header>

      <nav className="nav" aria-label="Primary navigation">
        {navigation.map((item) => (
          <button
            key={item.id}
            className={view === item.id ? 'active' : ''}
            type="button"
            onClick={() => setView(item.id)}
          >
            {item.label}
          </button>
        ))}
      </nav>

      {view === 'overview' && <OverviewPage report={report} />}
      {view === 'events' && <EventsPage events={report?.events ?? []} />}
      {view === 'timeline' && <TimelinePage events={report?.events ?? []} />}
      {view === 'findings' && <FindingsPage findings={report?.findings ?? []} />}
      {view === 'sessions' && <SessionsPage sessions={report?.sessions ?? []} />}
      {view === 'import' && <ImportPage report={report} onReport={(nextReport) => { setReport(nextReport); setView('overview'); }} onClear={() => setReport(null)} />}
    </main>
  );
}