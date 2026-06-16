'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import { listReports, getReportContent, ScanReport } from '@/lib/api';

export default function ReportsPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reports, setReports] = useState<{ filename: string; report: ScanReport }[]>([]);

  useEffect(() => {
    async function loadReports() {
      try {
        const filenames = await listReports();
        const loaded = await Promise.all(
          filenames.map(async name => {
            try {
              const report = await getReportContent(name);
              return { filename: name, report };
            } catch {
              return null;
            }
          })
        );
        const filtered = loaded.filter(
          (item): item is { filename: string; report: ScanReport } => item !== null
        );

        // Sort by timestamp descending
        const sorted = filtered.sort((a, b) => {
          const tA = new Date(a.report.scan_timestamp || 0).getTime();
          const tB = new Date(b.report.scan_timestamp || 0).getTime();
          return tB - tA;
        });

        setReports(sorted);
        setLoading(false);
      } catch (err: unknown) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        setError(errorMsg || 'Failed to retrieve security reports.');
        setLoading(false);
      }
    }
    loadReports();
  }, []);

  const getSeverityGlowClass = (report: ScanReport) => {
    const findings = report.findings || [];
    const hasCritical = findings.some(f => (f.severity || '').toUpperCase() === 'CRITICAL');
    const hasHigh = findings.some(f => (f.severity || '').toUpperCase() === 'HIGH');

    if (hasCritical) return 'border-red-900/50 hover:border-red-800 bg-red-950/5';
    if (hasHigh) return 'border-orange-900/50 hover:border-orange-800 bg-orange-950/5';
    return 'border-zinc-800 hover:border-zinc-700 bg-zinc-900/40';
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh] space-y-4">
        <div className="w-12 h-12 border-4 border-purple-500 border-t-transparent rounded-full animate-spin"></div>
        <p className="text-zinc-400 font-mono text-sm">Loading reports catalogue...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="max-w-2xl mx-auto border border-red-900/50 bg-red-950/15 text-red-300 text-sm rounded-xl p-4 font-mono">
        [ERROR] {error}
      </div>
    );
  }

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Header */}
      <div>
        <h3 className="text-2xl font-bold text-white">Scan Reports Catalogue</h3>
        <p className="text-sm text-zinc-400">Browse historical security scan results and view detailed taint flows.</p>
      </div>

      {reports.length === 0 ? (
        <div className="bg-zinc-900/40 border border-zinc-800 rounded-2xl p-12 text-center text-zinc-500 font-mono text-sm">
          No reports found. Go to &quot;Security Scan&quot; on the sidebar to trigger a scanner run.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {reports.map(({ filename, report }) => {
            const dateStr = new Date(report.scan_timestamp).toLocaleString();
            const findingsCount = (report.findings || []).length;
            const critCount = (report.findings || []).filter(f => (f.severity || '').toUpperCase() === 'CRITICAL').length;
            const highCount = (report.findings || []).filter(f => (f.severity || '').toUpperCase() === 'HIGH').length;

            return (
              <div
                key={filename}
                className={`border rounded-2xl p-6 flex flex-col justify-between space-y-4 transition-all duration-200 ${getSeverityGlowClass(report)}`}
              >
                <div className="space-y-2">
                  <div className="flex justify-between items-start gap-4">
                    <h4 className="font-semibold text-zinc-100 text-sm truncate max-w-sm" title={report.scan_target}>
                      {report.scan_target}
                    </h4>
                    <span className="text-[10px] text-zinc-500 font-mono bg-zinc-950 px-2 py-1 rounded border border-zinc-800 shrink-0">
                      {report.metadata.language || 'Report'}
                    </span>
                  </div>

                  <div className="text-xs text-zinc-400 font-mono space-y-1">
                    <div>Date: {dateStr}</div>
                    <div>Source: {report.scanner_name}</div>
                  </div>
                </div>

                <div className="flex justify-between items-center pt-2 border-t border-zinc-800/40">
                  <div className="flex space-x-3 text-xs font-mono">
                    <span className="text-zinc-400">
                      Findings: <strong className="text-zinc-200">{findingsCount}</strong>
                    </span>
                    {critCount > 0 && (
                      <span className="text-red-400">
                        Critical: <strong>{critCount}</strong>
                      </span>
                    )}
                    {highCount > 0 && (
                      <span className="text-orange-400">
                        High: <strong>{highCount}</strong>
                      </span>
                    )}
                  </div>

                  <Link
                    href={`/reports/${filename}`}
                    className="border border-zinc-700 bg-zinc-800/50 hover:bg-zinc-800 text-zinc-100 font-semibold px-3 py-1.5 rounded-lg text-xs transition-colors"
                  >
                    Open Details
                  </Link>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
