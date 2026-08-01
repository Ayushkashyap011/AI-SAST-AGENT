import React from 'react';
import type { SecurityReport, VulnerabilityFinding } from '../types/sast';
import { AlertOctagon, AlertTriangle, AlertCircle, ShieldCheck, Zap, Bug, Layers } from 'lucide-react';

interface DashboardProps {
  report: SecurityReport;
  onSelectFinding: (finding: VulnerabilityFinding) => void;
  onSwitchToAnalyzer: () => void;
}

export const Dashboard: React.FC<DashboardProps> = ({
  report,
  onSelectFinding,
  onSwitchToAnalyzer
}) => {
  const { summary, findings, totalFilesScanned, totalLinesScanned, scanDurationMs, owaspBreakdown } = report;

  const totalFindings = findings.length;

  return (
    <div className="dashboard-view">
      {/* Top Metric Cards */}
      <div className="metrics-grid">
        <div className="metric-card critical">
          <div className="metric-header">
            <AlertOctagon size={24} />
            <span>Critical Risk</span>
          </div>
          <div className="metric-value">{summary.critical}</div>
          <div className="metric-footer">Immediate Remediation Required</div>
        </div>

        <div className="metric-card high">
          <div className="metric-header">
            <AlertTriangle size={24} />
            <span>High Severity</span>
          </div>
          <div className="metric-value">{summary.high}</div>
          <div className="metric-footer">High Exploitability Vulnerabilities</div>
        </div>

        <div className="metric-card medium">
          <div className="metric-header">
            <AlertCircle size={24} />
            <span>Medium / Low</span>
          </div>
          <div className="metric-value">{summary.medium + summary.low}</div>
          <div className="metric-footer">Security Misconfigurations</div>
        </div>

        <div className="metric-card info">
          <div className="metric-header">
            <ShieldCheck size={24} />
            <span>Scan Efficiency</span>
          </div>
          <div className="metric-value">{scanDurationMs}ms</div>
          <div className="metric-footer">{totalFilesScanned} Files ({totalLinesScanned} Lines)</div>
        </div>
      </div>

      {/* OWASP & Risk Analysis Layout */}
      <div className="dashboard-columns">
        {/* Left Column: OWASP Top 10 Breakdown */}
        <div className="dashboard-panel">
          <h3 className="panel-title">
            <Layers size={18} />
            OWASP Top 10 Category Distribution
          </h3>
          <div className="owasp-list">
            {Object.keys(owaspBreakdown).length === 0 ? (
              <div className="empty-state">No OWASP violations detected.</div>
            ) : (
              Object.entries(owaspBreakdown).map(([category, count]) => (
                <div key={category} className="owasp-item">
                  <div className="owasp-label">
                    <span>{category}</span>
                    <span className="owasp-badge">{count} findings</span>
                  </div>
                  <div className="owasp-progress-bg">
                    <div
                      className="owasp-progress-fill"
                      style={{ width: `${Math.min(100, (count / totalFindings) * 100)}%` }}
                    />
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Right Column: Top Identified Vulnerabilities */}
        <div className="dashboard-panel">
          <div className="panel-header-flex">
            <h3 className="panel-title">
              <Bug size={18} />
              Identified Security Vulnerabilities ({totalFindings})
            </h3>
            <button className="text-btn" onClick={onSwitchToAnalyzer}>
              View in Code Editor &rarr;
            </button>
          </div>

          <div className="findings-table-wrapper">
            <table className="findings-table">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Vulnerability</th>
                  <th>CWE</th>
                  <th>File & Line</th>
                  <th>AI Verification</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {findings.map(finding => (
                  <tr key={finding.id} className="finding-row" onClick={() => { onSwitchToAnalyzer(); onSelectFinding(finding); }}>
                    <td>
                      <span className={`severity-badge ${finding.severity.toLowerCase()}`}>
                        {finding.severity}
                      </span>
                    </td>
                    <td className="finding-title-cell">
                      <strong>{finding.title}</strong>
                      <span className="finding-owasp">{finding.owaspCategory}</span>
                    </td>
                    <td><code className="cwe-tag">{finding.cwe}</code></td>
                    <td><code className="path-tag">{finding.filePath}:{finding.lineNumber}</code></td>
                    <td>
                      <span className="ai-verified-tag">
                        <Zap size={12} /> True Positive
                      </span>
                    </td>
                    <td>
                      <button className="inspect-btn">Inspect & Patch</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};
