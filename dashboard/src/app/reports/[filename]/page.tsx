'use client';

import React, { useEffect, useState, use } from 'react';
import { getReportContent, applyPatch, ScanReport, Finding, PatchResponse } from '@/lib/api';
import Link from 'next/link';

export default function ReportDetailPage({ params }: { params: Promise<{ filename: string }> }) {
  const { filename } = use(params);
  
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<ScanReport | null>(null);
  
  // Selected finding for side-panel detail view
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  
  // Patch states
  const [patching, setPatching] = useState(false);
  const [patchResult, setPatchResult] = useState<PatchResponse | null>(null);
  const [patchedLines, setPatchedLines] = useState<Record<string, boolean>>({});

  useEffect(() => {
    async function loadReport() {
      try {
        const data = await getReportContent(filename);
        setReport(data);
        if (data.findings && data.findings.length > 0) {
          setSelectedFinding(data.findings[0]);
        }
        setLoading(false);
      } catch (err: unknown) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        setError(errorMsg || 'Failed to retrieve report content.');
        setLoading(false);
      }
    }
    loadReport();
  }, [filename]);

  const handleApplyPatch = async (finding: Finding) => {
    setPatching(true);
    setPatchResult(null);
    try {
      const res = await applyPatch({
        file_path: finding.file_path,
        findings: [finding],
      });
      setPatchResult(res);
      if (res.success) {
        // Mark as patched in local state
        setPatchedLines(prev => ({
          ...prev,
          [`${finding.file_path}:${finding.line_number}`]: true,
        }));
      }
    } catch (err: unknown) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      setPatchResult({
        success: false,
        is_ai_patch: false,
        message: errorMsg || 'Failed to apply patch.',
        patched_code: null,
      });
    } finally {
      setPatching(false);
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

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh] space-y-4">
        <div className="w-12 h-12 border-4 border-purple-500 border-t-transparent rounded-full animate-spin"></div>
        <p className="text-zinc-400 font-mono text-sm">Parsing scan telemetries...</p>
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="max-w-2xl mx-auto border border-red-900/50 bg-red-950/15 text-red-300 text-sm rounded-xl p-4 font-mono">
        [ERROR] {error || 'Report not found.'}
      </div>
    );
  }

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Top Breadcrumb */}
      <div className="flex items-center space-x-2 text-xs font-mono text-zinc-500">
        <Link href="/reports" className="hover:text-zinc-300 transition-colors">Reports</Link>
        <span>/</span>
        <span className="text-zinc-300 truncate max-w-xs">{filename}</span>
      </div>

      {/* Overview Metadata */}
      <div className="bg-zinc-900/40 border border-zinc-800 rounded-2xl p-6 flex flex-col md:flex-row md:items-center justify-between gap-6">
        <div className="space-y-1">
          <h3 className="text-xl font-bold text-zinc-100 truncate max-w-2xl" title={report.scan_target}>
            {report.scan_target}
          </h3>
          <p className="text-xs text-zinc-500 font-mono">
            Scanned on {new Date(report.scan_timestamp).toLocaleString()} with {report.scanner_name}
          </p>
        </div>

        <div className="flex items-center space-x-4">
          <div className="text-right font-mono">
            <div className="text-[10px] text-zinc-500 uppercase">Total findings</div>
            <div className="text-xl font-bold text-zinc-100">{report.total_findings}</div>
          </div>
          <div className="text-right font-mono">
            <div className="text-[10px] text-zinc-500 uppercase">Risk Level</div>
            <div className={`text-xl font-bold uppercase ${report.total_findings > 0 ? 'text-red-400' : 'text-green-400'}`}>
              {report.total_findings > 0 ? 'Threats' : 'Clear'}
            </div>
          </div>
        </div>
      </div>

      {/* Main split content pane */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        {/* Findings List (Left Pane) */}
        <div className="lg:col-span-5 space-y-4">
          <h4 className="text-sm font-semibold text-zinc-400 font-mono uppercase tracking-wider">Findings List</h4>
          
          {report.findings.length === 0 ? (
            <div className="bg-zinc-900/40 border border-zinc-800 rounded-xl p-8 text-center text-zinc-500 font-mono text-sm">
              Clean report. No threats detected.
            </div>
          ) : (
            <div className="space-y-3 max-h-[70vh] overflow-y-auto pr-2">
              {report.findings.map((finding, idx) => {
                const isSelected = selectedFinding === finding;
                const fileLabel = finding.file_path.split(/[/\\]/).pop();
                const isPatched = patchedLines[`${finding.file_path}:${finding.line_number}`];

                return (
                  <button
                    key={idx}
                    onClick={() => {
                      setSelectedFinding(finding);
                      setPatchResult(null);
                    }}
                    className={`w-full text-left border rounded-xl p-4 transition-all duration-200 block ${isSelected ? 'border-purple-500/80 bg-purple-950/10 shadow-lg shadow-purple-950/10' : 'border-zinc-800 hover:border-zinc-700 bg-zinc-900/30'}`}
                  >
                    <div className="flex justify-between items-start gap-4">
                      <div className="space-y-0.5">
                        <div className="font-semibold text-sm text-zinc-100">{finding.vulnerability_type}</div>
                        <div className="text-[10px] text-zinc-500 font-mono">{finding.rule_id}</div>
                      </div>

                      <span className={`px-2.5 py-0.5 rounded-full text-[9px] font-mono font-bold border ${getSeverityBadgeClass(finding.severity)}`}>
                        {finding.severity}
                      </span>
                    </div>

                    <div className="flex justify-between items-center mt-3 text-xs font-mono text-zinc-400 border-t border-zinc-800/40 pt-2">
                      <span>{fileLabel}:{finding.line_number}</span>
                      {isPatched ? (
                        <span className="text-green-400 text-[10px] font-bold">✓ Patched</span>
                      ) : (
                        <span className="text-zinc-600 group-hover:text-zinc-400">View details &rarr;</span>
                      )}
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {/* Detailed Pane (Right Pane) */}
        <div className="lg:col-span-7 space-y-6 bg-zinc-900/30 border border-zinc-800 rounded-2xl p-6">
          {selectedFinding ? (
            <div className="space-y-6">
              {/* Finding Header */}
              <div className="border-b border-zinc-800 pb-4 space-y-2">
                <div className="flex justify-between items-start gap-4">
                  <div>
                    <h3 className="text-lg font-bold text-zinc-200">{selectedFinding.vulnerability_type}</h3>
                    <p className="text-xs text-zinc-500 font-mono">CWE ID: {selectedFinding.cwe_id || 'N/A'}</p>
                  </div>
                  <span className={`px-3 py-1 rounded-full text-[10px] font-mono font-bold border ${getSeverityBadgeClass(selectedFinding.severity)}`}>
                    {selectedFinding.severity}
                  </span>
                </div>
              </div>

              {/* Taint Flow Description */}
              <div className="space-y-2.5">
                <h5 className="text-[10px] font-semibold text-zinc-400 font-mono uppercase tracking-wider">Vulnerability Analysis</h5>
                <div className="bg-zinc-950/40 border border-zinc-800/80 rounded-xl p-4 space-y-3 text-sm font-mono text-zinc-300">
                  {selectedFinding.source && (
                    <div>
                      <span className="text-xs text-purple-400 uppercase font-semibold">Taint Source :</span>
                      <code className="bg-zinc-900 border border-zinc-800 px-2 py-0.5 rounded text-xs ml-2 text-zinc-200">
                        {selectedFinding.source}
                      </code>
                    </div>
                  )}
                  {selectedFinding.sink && (
                    <div>
                      <span className="text-xs text-pink-400 uppercase font-semibold">Taint Sink   :</span>
                      <code className="bg-zinc-900 border border-zinc-800 px-2 py-0.5 rounded text-xs ml-2 text-zinc-200">
                        {selectedFinding.sink}
                      </code>
                    </div>
                  )}
                  <div>
                    <span className="text-xs text-zinc-400 uppercase font-semibold">File Location:</span>
                    <span className="text-zinc-200 ml-2 text-xs truncate block md:inline-block max-w-sm" title={selectedFinding.file_path}>
                      {selectedFinding.file_path}
                    </span>
                  </div>
                </div>
              </div>

              {/* Code Snippet */}
              {selectedFinding.code_snippet && (
                <div className="space-y-2.5">
                  <h5 className="text-[10px] font-semibold text-zinc-400 font-mono uppercase tracking-wider">Vulnerable Code Snippet</h5>
                  <div className="bg-zinc-950 border border-zinc-800 rounded-xl overflow-hidden font-mono text-xs">
                    <div className="bg-zinc-900 px-4 py-2 border-b border-zinc-800/60 text-zinc-500 text-[10px] flex justify-between">
                      <span>Line {selectedFinding.line_number}</span>
                      <span>Python</span>
                    </div>
                    <pre className="p-4 overflow-x-auto text-red-400 bg-red-950/5">
                      <code>{selectedFinding.code_snippet}</code>
                    </pre>
                  </div>
                </div>
              )}

              {/* Recommendation */}
              <div className="space-y-2.5">
                <h5 className="text-[10px] font-semibold text-zinc-400 font-mono uppercase tracking-wider">Remediation Advice</h5>
                <div className="bg-zinc-950/20 border border-zinc-800/80 rounded-xl p-4 text-xs font-mono text-zinc-400 leading-relaxed whitespace-pre-wrap">
                  {selectedFinding.recommendation}
                </div>
              </div>

              {/* Auto Patch Action */}
              <div className="pt-4 border-t border-zinc-800">
                <button
                  onClick={() => handleApplyPatch(selectedFinding)}
                  disabled={patching || patchedLines[`${selectedFinding.file_path}:${selectedFinding.line_number}`]}
                  className={`w-full py-3 rounded-xl font-semibold text-xs font-mono transition-all duration-300 flex items-center justify-center space-x-2.5 ${patching ? 'bg-purple-950/20 border border-purple-900/50 text-purple-400 cursor-not-allowed' : patchedLines[`${selectedFinding.file_path}:${selectedFinding.line_number}`] ? 'bg-green-950/20 border border-green-900/50 text-green-400 cursor-not-allowed' : 'bg-gradient-to-r from-purple-500 to-pink-500 hover:opacity-90 text-white'}`}
                >
                  {patching ? (
                    <>
                      <div className="w-4 h-4 border-2 border-purple-400 border-t-transparent rounded-full animate-spin"></div>
                      <span>Synthesizing Remediation Patch...</span>
                    </>
                  ) : patchedLines[`${selectedFinding.file_path}:${selectedFinding.line_number}`] ? (
                    <span>Patch Applied &amp; Verified</span>
                  ) : (
                    <span>🩹 Apply Remediation Auto-Patch</span>
                  )}
                </button>
              </div>

              {/* Patch result output */}
              {patchResult && (
                <div className={`border rounded-xl p-4 space-y-3 font-mono text-xs ${patchResult.success ? 'bg-green-950/15 border-green-900/50 text-green-300' : 'bg-red-950/15 border-red-900/50 text-red-300'}`}>
                  <div className="font-semibold uppercase tracking-wider">
                    {patchResult.success ? '✓ Patch Success' : '✗ Patch Failed'}
                  </div>
                  <div>{patchResult.message}</div>
                  
                  {patchResult.success && patchResult.patched_code && (
                    <div className="space-y-2 mt-2">
                      <div className="text-[10px] text-zinc-500 uppercase">Remediated Code Preview:</div>
                      <pre className="bg-zinc-950 p-3 rounded border border-zinc-800 text-[10px] overflow-x-auto text-zinc-300 max-h-48">
                        <code>{patchResult.patched_code}</code>
                      </pre>
                    </div>
                  )}
                </div>
              )}
            </div>
          ) : (
            <div className="h-64 flex items-center justify-center text-zinc-500 font-mono text-sm text-center">
              Select a finding from the left pane to view flow metrics and execute AI patches.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
