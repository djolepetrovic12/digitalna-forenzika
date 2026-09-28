import React from 'react';
import { analyzeEvtxFiles, EvtxAnalysisReport } from '../api/analysis';

interface ImportPageProps {
  report: EvtxAnalysisReport | null;
  onReport: (report: EvtxAnalysisReport) => void;
  onClear: () => void;
}

export function ImportPage({ report, onReport, onClear }: ImportPageProps) {
  const [status, setStatus] = React.useState<'idle' | 'uploading' | 'analyzing' | 'complete'>('idle');
  const [error, setError] = React.useState<string | null>(null);

  async function handleFileChange(event: React.ChangeEvent<HTMLInputElement>) {
    const files = Array.from(event.target.files ?? []);
    if (!files.length) return;

    setError(null);
    setStatus('uploading');
    try {
      setStatus('analyzing');
      const result = await analyzeEvtxFiles(files);
      onReport(result);
      setStatus('complete');
    } catch (reason: unknown) {
      setStatus('idle');
      setError(reason instanceof Error ? reason.message : 'Unable to analyze the EVTX file.');
    }
  }

  return (
    <section className="import-panel">
      <div className="import-copy">
        <p className="eyebrow">Case evidence</p>
        <h2>Import EVTX evidence</h2>
        <p>Select one or more files to analyze together. Results remain in memory for this session.</p>
        <label className="file-button">
          Choose EVTX files
          <input type="file" accept=".evtx" multiple onChange={handleFileChange} />
        </label>
        {status === 'uploading' && <p role="status">Uploading file...</p>}
        {status === 'analyzing' && <p role="status">Parsing and running analysis...</p>}
        {status === 'complete' && <p role="status">Analysis complete.</p>}
        {error && <p className="error" role="alert">{error}</p>}
      </div>

      {report && (
        <div className="import-report">
          <div className="report-heading">
            <div>
              <p className="eyebrow">Latest report</p>
              <h3>{report.filename}</h3>
            </div>
              <span className="badge">In-memory analysis</span>
          </div>
          <div className="grid report-grid">
            <div className="card"><span className="metric-label">Records</span><strong className="metric">{report.record_count}</strong></div>
            <div className="card"><span className="metric-label">Sessions</span><strong className="metric">{report.sessions.length}</strong></div>
            <div className="card"><span className="metric-label">Findings</span><strong className="metric">{report.findings.length}</strong></div>
          </div>
          <p><strong>Provider:</strong> {report.providers.join(', ') || 'Unknown'}</p>
          <p><strong>Channel:</strong> {report.channels.join(', ') || 'Unknown'}</p>
          {report.files?.map((file) => (
            <p key={`${file.filename}-${file.sha256}`}>
              <strong>{file.filename}</strong> {file.record_count.toLocaleString()} records · SHA-256: {file.sha256}
            </p>
          ))}
          <button className="secondary-button" type="button" onClick={onClear}>Clear in-memory report</button>
        </div>
      )}
    </section>
  );
}