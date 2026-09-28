import { apiClient } from './client';
import { EventRecord } from '../types/event';
import { Finding } from '../types/finding';
import { SessionRecord } from '../types/session';

export interface EvtxAnalysisReport {
  filename: string;
  record_count: number;
  files: AnalyzedFileReport[];
  providers: string[];
  channels: string[];
  event_id_counts: Record<string, number>;
  events: EventRecord[];
  findings: Finding[];
  sessions: SessionRecord[];
}

export interface AnalyzedFileReport {
  filename: string;
  sha256: string;
  file_size: number;
  record_count: number;
}

export async function analyzeEvtx(file: File): Promise<EvtxAnalysisReport> {
  return analyzeEvtxFiles([file]);
}

export async function analyzeEvtxFiles(files: File[]): Promise<EvtxAnalysisReport> {
  const formData = new FormData();
  files.forEach((file) => formData.append('files', file));
  return apiClient.postFile<EvtxAnalysisReport>('/api/analyze/evtx', formData);
}