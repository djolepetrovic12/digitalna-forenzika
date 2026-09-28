import React from 'react';
import { EvtxAnalysisReport } from '../api/analysis';

interface OverviewPageProps {
  report: EvtxAnalysisReport | null;
}

export function OverviewPage({ report }: OverviewPageProps) {
  if (!report) {
    return (
      <section className="empty-state">
        <p className="eyebrow">Ready for evidence</p>
        <h2>Upload an EVTX file to begin</h2>
        <p>Analysis is held in memory and is discarded when you clear it or reload the app.</p>
      </section>
    );
  }

  return (
    <div>
      <p className="eyebrow">Latest analysis</p>
      <h2>{report.filename}</h2>
      <div className="grid">
        <section className="card"><span className="metric-label">Events</span><strong className="metric">{report.record_count}</strong></section>
        <section className="card"><span className="metric-label">Findings</span><strong className="metric">{report.findings.length}</strong></section>
        <section className="card"><span className="metric-label">Sessions</span><strong className="metric">{report.sessions.length}</strong></section>
      </div>
    </div>
  );
}
