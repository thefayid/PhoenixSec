'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import { listReports, getReportContent, ScanReport, fetchHealth } from '@/lib/api';

export default function OverviewPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [healthStatus, setHealthStatus] = useState<boolean>(false);
  const [stats, setStats] = useState({
    totalScans: 0,
    totalFindings: 0,
    criticalCount: 0,
    highCount: 0,
    mediumCount: 0,
    lowCount: 0,
    infoCount: 0,
  });
  const [recentReports, setRecentReports] = useState<{ name: string; report: ScanReport }[]>([]);

  useEffect(() => {
    async function loadStats() {
      try {
        // Check health
        try {
          await fetchHealth();
          setHealthStatus(true);
        } catch {
          setHealthStatus(false);
          setLoading(false);
          return;
        }

        const reportsList = await listReports();
        setStats(prev => ({ ...prev, totalScans: reportsList.length }));

        // Load all reports contents in parallel to aggregate stats
        const reportPromises = reportsList.map(async name => {
          try {
            const report = await getReportContent(name);
            return { name, report };
          } catch {
            return null;
          }
        });

        const loadedReports = (await Promise.all(reportPromises)).filter(
          (r): r is { name: string; report: ScanReport } => r !== null
        );

        let findingsTotal = 0;
        let crit = 0;
        let high = 0;
        let med = 0;
        let low = 0;
        let info = 0;

        for (const item of loadedReports) {
          const findings = item.report.findings || [];
          findingsTotal += findings.length;

          for (const f of findings) {
            const sev = (f.severity || 'INFO').toUpperCase();
            if (sev === 'CRITICAL') crit++;
            else if (sev === 'HIGH') high++;
            else if (sev === 'MEDIUM') med++;
            else if (sev === 'LOW') low++;
            else info++;
          }
        }

        setStats({
          totalScans: reportsList.length,
          totalFindings: findingsTotal,
          criticalCount: crit,
          highCount: high,
          mediumCount: med,
          lowCount: low,
          infoCount: info,
        });

        // Get latest 5 reports sorted by scan timestamp
        const sorted = loadedReports.sort((a, b) => {
          const tA = new Date(a.report.scan_timestamp || 0).getTime();
          const tB = new Date(b.report.scan_timestamp || 0).getTime();
          return tB - tA;
        });

        setRecentReports(sorted.slice(0, 5));
        setLoading(false);
      } catch (err: unknown) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        setError(errorMsg || 'Failed to aggregate scan statistics.');
        setLoading(false);
      }
    }

    loadStats();
  }, []);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh] space-y-4">
        <div className="w-12 h-12 border-4 border-purple-500 border-t-transparent rounded-full animate-spin"></div>
        <p className="text-zinc-400 font-mono text-sm">Aggregating vulnerability data...</p>
      </div>
    );
  }

  if (!healthStatus) {
    return (
      <div className="max-w-2xl mx-auto border border-red-900/50 bg-red-950/20 backdrop-blur-md rounded-2xl p-8 space-y-6 mt-12">
        <div className="flex items-center space-x-4">
          <span className="text-4xl">⚠️</span>
          <div>
            <h3 className="text-xl font-bold text-red-400">PhoenixSec Backend Offline</h3>
            <p className="text-sm text-zinc-400">Unable to establish connection to the FastAPI scanning server.</p>
          </div>
        </div>

        <div className="bg-black/40 border border-zinc-800 rounded-xl p-4 space-y-3">
          <p className="text-xs text-zinc-400 font-mono">Run the backend server to enable scans and report browsing:</p>
          <pre className="text-xs text-purple-400 font-mono bg-zinc-950 p-3 rounded-lg border border-zinc-800 overflow-x-auto">
            uvicorn phoenixsec.api.main:app --host 127.0.0.1 --port 8080 --reload
          </pre>
        </div>

        <button
          onClick={() => window.location.reload()}
          className="w-full bg-red-900/40 border border-red-800 hover:bg-red-800/50 text-red-200 font-medium px-4 py-2.5 rounded-lg text-sm transition-all duration-200"
        >
          Retry Connection
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Page Header */}
      <div>
        <h3 className="text-2xl font-bold text-white">Vulnerability Posture</h3>
        <p className="text-sm text-zinc-400">Real-time overview of security scan telemetry and repository health.</p>
      </div>

      {error && (
        <div className="border border-red-900/50 bg-red-950/15 text-red-300 text-sm rounded-xl p-4 font-mono">
          [ERROR] {error}
        </div>
      )}

      {/* Grid Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        {/* Total Scans */}
        <div className="bg-zinc-900/40 border border-zinc-800 rounded-xl p-6 flex flex-col justify-between h-32 hover:border-zinc-700 transition-all duration-200">
          <span className="text-xs text-zinc-400 font-mono uppercase tracking-wider">Total Scans Run</span>
          <span className="text-3xl font-bold font-mono text-zinc-100">{stats.totalScans}</span>
        </div>

        {/* Total Findings */}
        <div className="bg-zinc-900/40 border border-zinc-800 rounded-xl p-6 flex flex-col justify-between h-32 hover:border-zinc-700 transition-all duration-200">
          <span className="text-xs text-zinc-400 font-mono uppercase tracking-wider">Total Findings</span>
          <span className="text-3xl font-bold font-mono text-zinc-100">{stats.totalFindings}</span>
        </div>

        {/* Critical Vulnerabilities */}
        <div className={`border rounded-xl p-6 flex flex-col justify-between h-32 transition-all duration-200 ${stats.criticalCount > 0 ? 'bg-red-950/20 border-red-900/50 shadow-lg shadow-red-950/20 hover:border-red-800' : 'bg-zinc-900/40 border-zinc-800 hover:border-zinc-700'}`}>
          <span className="text-xs text-zinc-400 font-mono uppercase tracking-wider">Critical Issues</span>
          <span className={`text-3xl font-bold font-mono ${stats.criticalCount > 0 ? 'text-red-400' : 'text-zinc-100'}`}>
            {stats.criticalCount}
          </span>
        </div>

        {/* High Vulnerabilities */}
        <div className={`border rounded-xl p-6 flex flex-col justify-between h-32 transition-all duration-200 ${stats.highCount > 0 ? 'bg-orange-950/20 border-orange-900/50 shadow-lg shadow-orange-950/20 hover:border-orange-800' : 'bg-zinc-900/40 border-zinc-800 hover:border-zinc-700'}`}>
          <span className="text-xs text-zinc-400 font-mono uppercase tracking-wider">High Issues</span>
          <span className={`text-3xl font-bold font-mono ${stats.highCount > 0 ? 'text-orange-400' : 'text-zinc-100'}`}>
            {stats.highCount}
          </span>
        </div>
      </div>

      {/* Stats Breakdown Card */}
      <div className="bg-zinc-900/40 border border-zinc-800 rounded-2xl p-6">
        <h4 className="text-sm font-semibold text-zinc-300 font-mono uppercase tracking-wider mb-6">Severity Distribution</h4>
        
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <div className="bg-zinc-950/40 border border-zinc-800/80 rounded-xl p-4 text-center">
            <span className="text-xs font-semibold text-red-500 font-mono uppercase">Critical</span>
            <div className="text-2xl font-bold font-mono text-red-400 mt-1">{stats.criticalCount}</div>
          </div>
          <div className="bg-zinc-950/40 border border-zinc-800/80 rounded-xl p-4 text-center">
            <span className="text-xs font-semibold text-orange-500 font-mono uppercase">High</span>
            <div className="text-2xl font-bold font-mono text-orange-400 mt-1">{stats.highCount}</div>
          </div>
          <div className="bg-zinc-950/40 border border-zinc-800/80 rounded-xl p-4 text-center">
            <span className="text-xs font-semibold text-yellow-500 font-mono uppercase">Medium</span>
            <div className="text-2xl font-bold font-mono text-yellow-400 mt-1">{stats.mediumCount}</div>
          </div>
          <div className="bg-zinc-950/40 border border-zinc-800/80 rounded-xl p-4 text-center">
            <span className="text-xs font-semibold text-blue-500 font-mono uppercase">Low</span>
            <div className="text-2xl font-bold font-mono text-blue-400 mt-1">{stats.lowCount}</div>
          </div>
          <div className="bg-zinc-950/40 border border-zinc-800/80 rounded-xl p-4 text-center col-span-2 md:col-span-1">
            <span className="text-xs font-semibold text-zinc-500 font-mono uppercase">Info</span>
            <div className="text-2xl font-bold font-mono text-zinc-400 mt-1">{stats.infoCount}</div>
          </div>
        </div>
      </div>

      {/* Recent Activity Section */}
      <div className="bg-zinc-900/40 border border-zinc-800 rounded-2xl overflow-hidden">
        <div className="p-6 border-b border-zinc-800 flex justify-between items-center">
          <h4 className="text-sm font-semibold text-zinc-300 font-mono uppercase tracking-wider">Recent Scan Operations</h4>
          <Link href="/reports" className="text-xs text-purple-400 hover:text-purple-300 transition-colors font-medium">
            View all reports &rarr;
          </Link>
        </div>

        {recentReports.length === 0 ? (
          <div className="p-8 text-center text-zinc-500 font-mono text-sm">
            No scan reports saved yet. Click &quot;Security Scan&quot; on the sidebar to run your first code scan.
          </div>
        ) : (
          <div className="divide-y divide-zinc-800/60">
            {recentReports.map(({ name, report }) => {
              const dateStr = new Date(report.scan_timestamp).toLocaleString();
              const hasCritical = (report.findings || []).some(f => (f.severity || '').toUpperCase() === 'CRITICAL');
              const hasHigh = (report.findings || []).some(f => (f.severity || '').toUpperCase() === 'HIGH');
              const statusColor = hasCritical ? 'bg-red-500' : hasHigh ? 'bg-orange-500' : 'bg-green-500';

              return (
                <div key={name} className="p-6 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:bg-zinc-800/20 transition-all duration-200">
                  <div className="space-y-1">
                    <div className="flex items-center space-x-2.5">
                      <span className={`w-2 h-2 rounded-full ${statusColor}`}></span>
                      <span className="font-semibold text-zinc-200 text-sm truncate max-w-lg block">
                        {report.scan_target}
                      </span>
                    </div>
                    <div className="flex items-center space-x-4 text-xs text-zinc-500 font-mono">
                      <span>{dateStr}</span>
                      <span>&bull;</span>
                      <span>{(report.findings || []).length} issue(s)</span>
                      {report.metadata.language && (
                        <>
                          <span>&bull;</span>
                          <span>{report.metadata.language}</span>
                        </>
                      )}
                    </div>
                  </div>

                  <Link
                    href={`/reports/${name}`}
                    className="border border-zinc-700 bg-zinc-800/40 hover:bg-zinc-800 text-zinc-200 font-medium px-4 py-2 rounded-lg text-xs transition-colors self-start md:self-auto"
                  >
                    Open Report
                  </Link>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
