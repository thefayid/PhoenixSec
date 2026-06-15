// API Client for PhoenixSec Backend

const BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8080';

export interface Finding {
  rule_id: string;
  vulnerability_type: string;
  severity: string;
  confidence_score: number;
  recommendation: string;
  file_path: string;
  line_number: number | null;
  source: string | null;
  sink: string | null;
  code_snippet: string | null;
  cwe_id: string | null;
  references: string[];
}

export interface ScanReport {
  scan_target: string;
  scanner_name: string;
  scan_timestamp: string;
  total_findings: number;
  findings: Finding[];
  metadata: {
    language?: string;
    files_scanned?: number;
    duration_seconds?: number;
    repos_scanned_count?: number;
    repos_failed?: number;
    org_name?: string;
    [key: string]: unknown;
  };
}

export interface ScanRequest {
  target: string;
  severity: string;
  format: 'json' | 'html' | 'sarif' | 'text';
}

export interface AsyncScanResponse {
  task_id: string;
  status: string;
  message: string;
}

export interface TaskStatusResponse {
  task_id: string;
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';
  result: ScanReport | null;
  error: string | null;
}

export interface PatchRequest {
  file_path: string;
  findings: Partial<Finding>[];
}

export interface PatchResponse {
  success: boolean;
  is_ai_patch: boolean;
  message: string;
  patched_code: string | null;
}

export async function fetchHealth() {
  const res = await fetch(`${BASE_URL}/health`, { cache: 'no-store' });
  if (!res.ok) throw new Error('API Health check failed');
  return res.json();
}

export async function triggerScanSync(req: ScanRequest): Promise<ScanReport> {
  const res = await fetch(`${BASE_URL}/api/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(req),
    cache: 'no-store',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Failed to trigger scan' }));
    throw new Error(err.detail || 'Failed to trigger scan');
  }
  return res.json();
}

export async function triggerScanAsync(req: ScanRequest): Promise<AsyncScanResponse> {
  const res = await fetch(`${BASE_URL}/api/scan/async`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(req),
    cache: 'no-store',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Failed to trigger async scan' }));
    throw new Error(err.detail || 'Failed to trigger async scan');
  }
  return res.json();
}

export async function getTaskStatus(taskId: string): Promise<TaskStatusResponse> {
  const res = await fetch(`${BASE_URL}/api/scan/tasks/${taskId}`, {
    cache: 'no-store',
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch task status for ${taskId}`);
  }
  return res.json();
}

export async function listReports(): Promise<string[]> {
  const res = await fetch(`${BASE_URL}/api/reports`, { cache: 'no-store' });
  if (!res.ok) throw new Error('Failed to list reports');
  const data = await res.json();
  return data.reports || [];
}

export async function getReportContent(filename: string): Promise<ScanReport> {
  const res = await fetch(`${BASE_URL}/api/reports/${filename}`, {
    cache: 'no-store',
  });
  if (!res.ok) throw new Error(`Failed to fetch report: ${filename}`);
  return res.json();
}

export async function applyPatch(req: PatchRequest): Promise<PatchResponse> {
  const res = await fetch(`${BASE_URL}/api/patch`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(req),
    cache: 'no-store',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Failed to apply patch' }));
    throw new Error(err.detail || 'Failed to apply patch');
  }
  return res.json();
}
