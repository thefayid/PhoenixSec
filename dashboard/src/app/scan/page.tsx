'use client';

import React, { useState, useEffect } from 'react';
import { triggerScanSync, triggerScanAsync, getTaskStatus, ScanReport, TaskStatusResponse } from '@/lib/api';

export default function ScanPage() {
  // Form inputs
  const [target, setTarget] = useState('');
  const [severity, setSeverity] = useState('LOW');
  const [isAsync, setIsAsync] = useState(false);

  // States
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  // Sync scan results
  const [report, setReport] = useState<ScanReport | null>(null);

  // Async task states
  const [taskId, setTaskId] = useState<string | null>(null);
  const [taskStatus, setTaskStatus] = useState<TaskStatusResponse | null>(null);

  // Poll async task status
  useEffect(() => {
    let intervalId: ReturnType<typeof setInterval> | undefined;
    if (taskId && isAsync) {
      intervalId = setInterval(async () => {
        try {
          const status = await getTaskStatus(taskId);
          setTaskStatus(status);
          if (status.status === 'COMPLETED' || status.status === 'FAILED') {
            clearInterval(intervalId);
            setSubmitting(false);
            if (status.result) {
              setReport(status.result);
            }
          }
        } catch (err: unknown) {
          const errorMsg = err instanceof Error ? err.message : String(err);
          setError(errorMsg || 'Error tracking background scan task.');
          clearInterval(intervalId);
          setSubmitting(false);
        }
      }, 2000);
    }
    return () => clearInterval(intervalId);
  }, [taskId, isAsync]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim()) {
      setError('Please provide a scan target path.');
      return;
    }

    setSubmitting(true);
    setError(null);
    setReport(null);
    setTaskId(null);
    setTaskStatus(null);

    const payload = {
      target: target.trim(),
      severity,
      format: 'json' as const,
    };

    try {
      if (isAsync) {
        const res = await triggerScanAsync(payload);
        setTaskId(res.task_id);
        setTaskStatus({ task_id: res.task_id, status: 'PENDING', result: null, error: null });
      } else {
        const res = await triggerScanSync(payload);
        setReport(res);
        setSubmitting(false);
      }
    } catch (err: unknown) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      setError(errorMsg || 'Failed to execute security scan.');
      setSubmitting(false);
    }
  };

  const getSeverityBadgeClass = (sev: string) => {
    const s = sev.toUpperCase();
    if (s === 'CRITICAL') return 'bg-red-500/10 text-red-400 border-red-500/20';
    if (s === 'HIGH') return 'bg-orange-500/10 text-orange-400 border-orange-500/20';
    if (s === 'MEDIUM') return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20';
    if (s === 'LOW') return 'bg-blue-500/10 text-blue-400 border-blue-500/20';
    return 'bg-zinc-500/10 text-zinc-400 border-zinc-500/20';
  };

  return (
    <div className="space-y-8 max-w-6xl mx-auto">
      {/* Header */}
      <div>
        <h3 className="text-2xl font-bold text-white">Security Pipeline Scan</h3>
        <p className="text-sm text-zinc-400 font-mono">Trigger real-time AST analysis and dependency vulnerability scans against local paths.</p>
      </div>

      {/* Form Card */}
      <div className="bg-zinc-900/40 border border-zinc-800 rounded-2xl p-6">
        <form onSubmit={handleSubmit} className="space-y-6">
          <div className="space-y-2">
            <label className="text-sm font-semibold text-zinc-300 font-mono uppercase tracking-wider block">
              Scan Target Path
            </label>
            <input
              type="text"
              placeholder="e.g. e:\Phoenix Sec\samples"
              value={target}
              onChange={e => setTarget(e.target.value)}
              className="w-full bg-zinc-950 border border-zinc-800 focus:border-purple-500 focus:ring-1 focus:ring-purple-500 rounded-xl px-4 py-3 text-sm text-zinc-200 font-mono transition-all duration-200 outline-none"
            />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Severity Filter */}
            <div className="space-y-2">
              <label className="text-sm font-semibold text-zinc-300 font-mono uppercase tracking-wider block">
                Minimum Severity Filter
              </label>
              <select
                value={severity}
                onChange={e => setSeverity(e.target.value)}
                className="w-full bg-zinc-950 border border-zinc-800 focus:border-purple-500 focus:ring-1 focus:ring-purple-500 rounded-xl px-4 py-3 text-sm text-zinc-200 transition-all duration-200 outline-none font-mono"
              >
                <option value="INFO">INFO</option>
                <option value="LOW">LOW</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="HIGH">HIGH</option>
                <option value="CRITICAL">CRITICAL</option>
              </select>
            </div>

            {/* Scan Mode Toggle */}
            <div className="space-y-2">
              <label className="text-sm font-semibold text-zinc-300 font-mono uppercase tracking-wider block">
                Execution Model
              </label>
              <div className="grid grid-cols-2 gap-3 bg-zinc-950 border border-zinc-800 p-1.5 rounded-xl">
                <button
                  type="button"
                  onClick={() => setIsAsync(false)}
                  className={`py-2 rounded-lg text-xs font-mono font-medium transition-all duration-200 ${!isAsync ? 'bg-zinc-800/80 text-zinc-100 border border-zinc-700/50' : 'text-zinc-500 hover:text-zinc-300'}`}
                >
                  Synchronous
                </button>
                <button
                  type="button"
                  onClick={() => setIsAsync(true)}
                  className={`py-2 rounded-lg text-xs font-mono font-medium transition-all duration-200 ${isAsync ? 'bg-zinc-800/80 text-zinc-100 border border-zinc-700/50' : 'text-zinc-500 hover:text-zinc-300'}`}
                >
                  Asynchronous
                </button>
              </div>
            </div>
          </div>

          <button
            type="submit"
            disabled={submitting}
            className={`w-full py-3 rounded-xl font-semibold text-sm transition-all duration-300 flex items-center justify-center space-x-2.5 ${submitting ? 'bg-purple-950/40 border border-purple-900/50 text-purple-400 cursor-not-allowed' : 'bg-gradient-to-r from-purple-500 to-pink-500 text-white shadow-lg shadow-purple-950/20 hover:opacity-90'}`}
          >
            {submitting ? (
              <>
                <div className="w-4 h-4 border-2 border-purple-400 border-t-transparent rounded-full animate-spin"></div>
                <span className="font-mono">Running Scan pipeline...</span>
              </>
            ) : (
              <span>Execute Scan Suite</span>
            )}
          </button>
        </form>
      </div>

      {/* Error Message */}
      {error && (
        <div className="border border-red-900/50 bg-red-950/15 text-red-300 text-sm rounded-xl p-4 font-mono">
          [ERROR] {error}
        </div>
      )}

      {/* Async Task Monitor */}
      {isAsync && taskStatus && (
        <div className="bg-zinc-900/40 border border-zinc-800 rounded-2xl p-6 space-y-4">
          <div className="flex justify-between items-center border-b border-zinc-800/60 pb-3">
            <h4 className="text-sm font-semibold text-zinc-300 font-mono uppercase tracking-wider">Background Task Status</h4>
            <span className="text-xs text-zinc-500 font-mono truncate max-w-xs block">Task ID: {taskId}</span>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 py-2">
            <div>
              <span className="text-[10px] text-zinc-500 uppercase font-mono">Status</span>
              <div className="text-sm font-bold font-mono mt-0.5 flex items-center space-x-2">
                <span className={`w-2 h-2 rounded-full ${taskStatus.status === 'RUNNING' ? 'bg-blue-500 animate-pulse' : taskStatus.status === 'COMPLETED' ? 'bg-green-500' : taskStatus.status === 'FAILED' ? 'bg-red-500' : 'bg-zinc-500'}`}></span>
                <span className="text-zinc-200">{taskStatus.status}</span>
              </div>
            </div>
            <div>
              <span className="text-[10px] text-zinc-500 uppercase font-mono">Target</span>
              <div className="text-sm font-bold font-mono mt-0.5 text-zinc-200 truncate">{target}</div>
            </div>
          </div>
          
          {taskStatus.status === 'FAILED' && (
            <div className="border border-red-950 bg-red-950/20 text-red-400 p-3 rounded-lg text-xs font-mono">
              Error details: {taskStatus.error}
            </div>
          )}
        </div>
      )}

      {/* Report Display */}
      {report && (
        <div className="space-y-6">
          {/* Summary Stats */}
          <div className="bg-zinc-900/40 border border-zinc-800 rounded-2xl p-6 space-y-6">
            <div className="border-b border-zinc-800 pb-4">
              <h4 className="text-base font-bold text-zinc-200">Scan Summary</h4>
              <p className="text-xs text-zinc-500 font-mono mt-1">Scanner: {report.scanner_name} | Target: {report.scan_target}</p>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="bg-zinc-950/40 border border-zinc-800/80 rounded-xl p-4">
                <span className="text-[10px] text-zinc-500 font-mono uppercase block">Total Findings</span>
                <span className="text-2xl font-bold font-mono text-zinc-100">{report.total_findings}</span>
              </div>
              <div className="bg-zinc-950/40 border border-zinc-800/80 rounded-xl p-4">
                <span className="text-[10px] text-zinc-500 font-mono uppercase block">Duration</span>
                <span className="text-2xl font-bold font-mono text-zinc-100">
                  {report.metadata.duration_seconds !== undefined ? `${report.metadata.duration_seconds.toFixed(2)}s` : 'N/A'}
                </span>
              </div>
              <div className="bg-zinc-950/40 border border-zinc-800/80 rounded-xl p-4">
                <span className="text-[10px] text-zinc-500 font-mono uppercase block">Files Scanned</span>
                <span className="text-2xl font-bold font-mono text-zinc-100">
                  {report.metadata.files_scanned !== undefined ? report.metadata.files_scanned : '1'}
                </span>
              </div>
              <div className="bg-zinc-950/40 border border-zinc-800/80 rounded-xl p-4">
                <span className="text-[10px] text-zinc-500 font-mono uppercase block">Risk Posture</span>
                <span className={`text-2xl font-bold font-mono uppercase ${report.total_findings > 0 ? 'text-red-400' : 'text-green-400'}`}>
                  {report.total_findings > 0 ? 'Threats Found' : 'Clear'}
                </span>
              </div>
            </div>
          </div>

          {/* Findings Table */}
          {report.findings && report.findings.length > 0 ? (
            <div className="bg-zinc-900/40 border border-zinc-800 rounded-2xl overflow-hidden">
              <div className="p-6 border-b border-zinc-800">
                <h4 className="text-sm font-semibold text-zinc-300 font-mono uppercase tracking-wider">Detected Vulnerabilities</h4>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm text-zinc-400 border-collapse">
                  <thead className="text-xs uppercase font-mono text-zinc-500 border-b border-zinc-800 bg-zinc-950/20">
                    <tr>
                      <th className="py-4 px-6">Vulnerability</th>
                      <th className="py-4 px-6 text-center">Severity</th>
                      <th className="py-4 px-6 text-center">CWE</th>
                      <th className="py-4 px-6">Location</th>
                      <th className="py-4 px-6 text-right">Confidence</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-800/60">
                    {report.findings.map((finding, idx) => {
                      const fileLabel = finding.file_path.split(/[/\\]/).pop();
                      return (
                        <tr key={idx} className="hover:bg-zinc-800/10 transition-colors">
                          <td className="py-4 px-6 font-semibold text-zinc-200">
                            <div className="space-y-0.5">
                              <div>{finding.vulnerability_type}</div>
                              <div className="text-[10px] font-mono text-zinc-500">{finding.rule_id}</div>
                            </div>
                          </td>
                          <td className="py-4 px-6 text-center">
                            <span className={`px-2.5 py-1 rounded-full text-[10px] font-mono font-bold border ${getSeverityBadgeClass(finding.severity)}`}>
                              {finding.severity}
                            </span>
                          </td>
                          <td className="py-4 px-6 text-center font-mono text-xs">{finding.cwe_id || 'N/A'}</td>
                          <td className="py-4 px-6 text-zinc-300 font-mono text-xs">
                            {fileLabel}:{finding.line_number}
                          </td>
                          <td className="py-4 px-6 text-right font-mono text-zinc-300">
                            {(finding.confidence_score * 100).toFixed(0)}%
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          ) : (
            <div className="bg-zinc-900/40 border border-zinc-800 rounded-2xl p-8 text-center text-zinc-500 font-mono text-sm">
              🚀 Excellent! No vulnerabilities matching the filter criteria were detected.
            </div>
          )}
        </div>
      )}
    </div>
  );
}
