import React from 'react';
import { EvtxAnalysisReport } from '../api/analysis';
import { ImportPage } from './ImportPage';

interface OverviewPageProps {
  report: EvtxAnalysisReport;
  onReport: (report: EvtxAnalysisReport) => void;
  onClear: () => void;
}

export function OverviewPage({ report, onReport, onClear }: OverviewPageProps) {
  return (
    <ImportPage report={report} onReport={onReport} onClear={onClear} />
  );
}
