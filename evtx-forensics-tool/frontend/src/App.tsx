import React from 'react';
import { EvtxAnalysisReport } from './api/analysis';
import { FindingsPage } from './pages/FindingsPage';
import { OverviewPage } from './pages/OverviewPage';
import { SessionsPage } from './pages/SessionsPage';
import { ImportPage } from './pages/ImportPage';
import { TimelinePage } from './pages/TimelinePage';

type View = 'overview' | 'timeline' | 'findings' | 'sessions';

const navigation: Array<{ id: View; label: string }> = [
  { id: 'overview', label: 'Overview' },
  { id: 'timeline', label: 'Timeline' },
  { id: 'findings', label: 'Findings' },
  { id: 'sessions', label: 'Sessions' },
];

export function App() {
  const [view, setView] = React.useState<View>('overview');
  const [report, setReport] = React.useState<EvtxAnalysisReport | null>(null);

  if (!report) {
    return (
      <main className="app app-import-only">
        <ImportPage report={null} onReport={setReport} onClear={() => setReport(null)} />
      </main>
    );
  }

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

      {view === 'overview' && <OverviewPage report={report} onReport={setReport} onClear={() => setReport(null)} />}
      {view === 'timeline' && <TimelinePage events={report.events} />}
      {view === 'findings' && <FindingsPage findings={report.findings} events={report.events} />}
      {view === 'sessions' && <SessionsPage sessions={report.sessions} events={report.events} />}
    </main>
  );
}