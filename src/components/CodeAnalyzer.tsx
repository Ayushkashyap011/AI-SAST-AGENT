import React, { useState } from 'react';
import type { SecurityReport, VulnerabilityFinding, PresetRepo, PresetFile } from '../types/sast';
import { FileCode, ShieldAlert, CheckCircle, Copy, Zap, Upload, FolderUp, Link as LinkIcon, RefreshCw } from 'lucide-react';
import JSZip from 'jszip';

interface CodeAnalyzerProps {
  report: SecurityReport;
  selectedRepo: PresetRepo;
  selectedFinding: VulnerabilityFinding | null;
  onSelectFinding: (finding: VulnerabilityFinding | null) => void;
  customCode: string;
  setCustomCode: (code: string) => void;
  onRunCustomScan: () => void;
  onAnalyzeCustomFiles: (repoName: string, files: PresetFile[]) => Promise<SecurityReport>;
  onResetWorkspace: () => void;
}

export const CodeAnalyzer: React.FC<CodeAnalyzerProps> = ({
  report,
  selectedRepo,
  selectedFinding,
  onSelectFinding,
  customCode,
  setCustomCode,
  onRunCustomScan,
  onAnalyzeCustomFiles,
  onResetWorkspace
}) => {
  const [activeFile, setActiveFile] = useState<PresetFile | null>(selectedRepo.files[0] || null);
  const [copied, setCopied] = useState(false);
  const [activeMode, setActiveMode] = useState<'preset' | 'custom' | 'zip' | 'url'>('url');
  const [repoUrl, setRepoUrl] = useState('');
  const [isFetchingUrl, setIsFetchingUrl] = useState(false);
  const [uploadStatus, setUploadStatus] = useState<string>('');
  const gutterRef = React.useRef<HTMLDivElement>(null);

  const handleModeSwitch = (mode: 'url' | 'zip' | 'custom') => {
    setActiveMode(mode);
    setActiveFile(null);
    setUploadStatus('');
    onSelectFinding(null);
    onResetWorkspace();
  };

  const handleZipUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    setUploadStatus('Extracting Zip contents...');

    try {
      const zip = await JSZip.loadAsync(file);
      const extractedFiles: PresetFile[] = [];

      for (const filename of Object.keys(zip.files)) {
        const zipEntry = zip.files[filename];
        if (zipEntry.dir) continue;

        const ext = filename.split('.').pop()?.toLowerCase();
        let lang: PresetFile['language'] = 'python';
        if (ext === 'ts' || ext === 'tsx') lang = 'typescript';
        else if (ext === 'js' || ext === 'jsx') lang = 'javascript';
        else if (ext === 'sql') lang = 'sql';
        else if (ext === 'py') lang = 'python';
        else continue;

        const content = await zipEntry.async('string');
        extractedFiles.push({
          name: filename.split('/').pop() || filename,
          path: filename,
          language: lang,
          content
        });
      }

      if (extractedFiles.length === 0) {
        setUploadStatus('No Python, TS, JS, or SQL source files found in zip.');
        return;
      }

      setUploadStatus(`Found ${extractedFiles.length} source code files. Running ARIES SAST Scan...`);
      onAnalyzeCustomFiles(file.name.replace('.zip', ''), extractedFiles);
      setActiveFile(extractedFiles[0]);
      setActiveMode('preset');
    } catch (err) {
      console.error(err);
      setUploadStatus('Error unpacking zip file.');
    }
  };

  const handleFetchGitHubRepo = async () => {
    if (!repoUrl) return;
    setIsFetchingUrl(true);
    setUploadStatus('Connecting to GitHub API...');

    try {
      let clean = repoUrl.trim();
      clean = clean.replace(/^https?:\/\/github\.com\//i, '').replace(/\.git$/i, '').replace(/\/$/, '');
      const parts = clean.split('/');
      if (parts.length < 2) {
        throw new Error('Invalid GitHub repository format. Use owner/repo or full GitHub link.');
      }
      const owner = parts[0];
      const repo = parts[1];

      setUploadStatus(`Fetching repository metadata for ${owner}/${repo}...`);
      const repoMetaRes = await fetch(`https://api.github.com/repos/${owner}/${repo}`);
      if (!repoMetaRes.ok) {
        if (repoMetaRes.status === 404) {
          throw new Error(`Repository "${owner}/${repo}" not found or is private.`);
        }
        throw new Error(`GitHub API rate limit or error (HTTP ${repoMetaRes.status}).`);
      }
      const repoMeta = await repoMetaRes.json();
      const defaultBranch = repoMeta.default_branch || 'main';

      setUploadStatus(`Reading file tree for branch "${defaultBranch}"...`);
      const treeRes = await fetch(`https://api.github.com/repos/${owner}/${repo}/git/trees/${defaultBranch}?recursive=1`);
      if (!treeRes.ok) {
        throw new Error(`Failed to fetch file tree for ${owner}/${repo}.`);
      }
      const treeData = await treeRes.json();
      const items = treeData.tree || [];

      const vendorDirs = [
        'node_modules', 'vendor', 'dist', 'build', 'out', 'coverage', '.next', '.nuxt',
        '.cache', '.git', '.github', '.idea', '.vscode', '__pycache__', '.venv', 'venv',
        'target', 'bin', 'obj', 'generated', 'tmp', 'temp', 'logs', 'public/vendor', 'static/vendor',
        'test', 'tests', 'spec', 'specs', 'cypress', '__tests__', 'test-results'
      ];

      const generatedLockFiles = [
        'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'poetry.lock', 'Cargo.lock', 'composer.lock'
      ];

      const frontendVendorLibs = [
        'jquery', 'bootstrap', 'react.production', 'react-dom.production', 'angular', 'vue.runtime',
        'lodash', 'underscore', 'moment', 'chart.js', 'morris', 'd3', 'leaflet', 'ckeditor', 'tinymce',
        'ace', 'codemirror', 'highlight.js', 'anime.js', 'fontawesome'
      ];

      const supportedExts = [
        '.py', '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.go', '.java', '.cs',
        '.php', '.rb', '.rs', '.kt', '.swift', 'dockerfile', '.yml', '.yaml', '.tf',
        '.sh', '.sql', '.env.example', 'package.json', 'requirements.txt', 'pyproject.toml',
        'go.mod', 'pom.xml', 'build.gradle', 'composer.json', 'Gemfile'
      ];

      let vendorCount = 0;
      let minifiedCount = 0;
      let generatedCount = 0;

      const codeItems = items
        .filter((item: any) => {
          if (item.type !== 'blob') return false;
          const path = item.path.toLowerCase();
          const fileName = path.split('/').pop() || '';

          // 1. Filter Vendor & Test Directories
          if (vendorDirs.some(dir => path.includes(`/${dir}/`) || path.startsWith(`${dir}/`))) {
            vendorCount++;
            return false;
          }

          // 2. Filter Vendor Frontend Libraries & Test Spec Files
          if (
            frontendVendorLibs.some(lib => fileName.includes(lib)) ||
            fileName.endsWith('_spec.js') ||
            fileName.endsWith('-test.js') ||
            fileName.endsWith('.test.js') ||
            fileName.endsWith('.spec.js') ||
            fileName.includes('test.js')
          ) {
            vendorCount++;
            return false;
          }

          // 3. Filter Generated & Lock Files
          if (generatedLockFiles.includes(fileName) || fileName.endsWith('.map')) {
            generatedCount++;
            return false;
          }

          // 4. Filter Minified Files
          if (fileName.endsWith('.min.js') || fileName.endsWith('.bundle.js') || fileName.endsWith('.chunk.js')) {
            minifiedCount++;
            return false;
          }

          // Check supported extension
          return supportedExts.some(ext => path.endsWith(ext) || fileName === ext);
        })
        .sort((a: any, b: any) => {
          const aPath = a.path.toLowerCase();
          const bPath = b.path.toLowerCase();
          const keyDirs = ['routes/', 'controllers/', 'services/', 'api/', 'lib/', 'server/', 'src/', 'app/', 'middleware/', 'auth/', 'models/', 'database/', 'db/', 'repositories/', 'utils/', 'config/'];
          const aScore = keyDirs.some(d => aPath.includes(d)) ? 1 : 0;
          const bScore = keyDirs.some(d => bPath.includes(d)) ? 1 : 0;
          return bScore - aScore;
        });

      if (codeItems.length === 0) {
        throw new Error('No application source files found in repository.');
      }

      setUploadStatus(`Fetching ${codeItems.length} application source files from raw.githubusercontent.com...`);

      const fetchedFiles: PresetFile[] = (await Promise.all(
        codeItems.map(async (item: any) => {
          const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${defaultBranch}/${item.path}`;
          const rawRes = await fetch(rawUrl);
          const content = await rawRes.text();

          // Skip minified JS files (avg line length > 500 chars or sourceMappingURL)
          const lines = content.split('\n');
          const avgLineLength = content.length / Math.max(1, lines.length);
          if ((avgLineLength > 500 || content.includes('sourceMappingURL=')) && (item.path.endsWith('.js') || item.path.endsWith('.cjs'))) {
            minifiedCount++;
            return null;
          }

          const ext = (item.path || '').split('.').pop()?.toLowerCase();
          const fileNameLower = (item.path || '').toLowerCase();

          let lang: PresetFile['language'] = 'javascript';
          if (fileNameLower.includes('dockerfile')) {
            lang = 'dockerfile';
          } else if (ext === 'py') {
            lang = 'python';
          } else if (ext === 'ts' || ext === 'tsx') {
            lang = 'typescript';
          } else if (ext === 'js' || ext === 'jsx' || ext === 'mjs' || ext === 'cjs') {
            lang = 'javascript';
          } else if (ext === 'sql') {
            lang = 'sql';
          }

          return {
            name: (item.path || '').split('/').pop() || item.path || 'unknown_file',
            path: item.path || 'unknown_file',
            language: lang,
            content
          };
        })
      )).filter((f): f is PresetFile => f !== null);

      setUploadStatus(`Successfully fetched ${fetchedFiles.length} application source files. Launching ARIES SAST Scan...`);
      const scanReport = await onAnalyzeCustomFiles(`${owner}/${repo}`, fetchedFiles);

      // Auto-select first file with detected vulnerabilities if available
      const firstVulnFinding = scanReport?.findings.find(f => fetchedFiles.some(ff => ff.path === f.filePath));
      if (firstVulnFinding) {
        const matchingFile = fetchedFiles.find(ff => ff.path === firstVulnFinding.filePath);
        if (matchingFile) {
          setActiveFile(matchingFile);
          onSelectFinding(firstVulnFinding);
        } else {
          setActiveFile(fetchedFiles[0]);
        }
      } else {
        setActiveFile(fetchedFiles[0]);
      }

      setActiveMode('preset');
    } catch (err: any) {
      console.error(err);
      setUploadStatus(err.message || 'Failed to fetch public repo. Ensure URL is correct.');
    } finally {
      setIsFetchingUrl(false);
    }
  };

  const handleSelectFinding = (finding: VulnerabilityFinding | null) => {
    onSelectFinding(finding);
    if (finding) {
      const targetFile = selectedRepo.files.find(f => f.path === finding.filePath);
      if (targetFile) {
        setActiveFile(targetFile);
        setActiveMode('preset');
      }
    }
  };

  const handleCopyDiff = (diff: string) => {
    navigator.clipboard.writeText(diff);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="analyzer-view">
      {/* Sidebar: Inputs & File Tree */}
      <div className="analyzer-sidebar">
        <div className="sidebar-section">
          <label className="sidebar-label">Select Input Method:</label>
          <div className="repo-buttons">
            <button
              className={`repo-selector-btn ${activeMode === 'url' ? 'active' : ''}`}
              onClick={() => handleModeSwitch('url')}
            >
              <LinkIcon size={16} />
              <div>
                <div className="repo-btn-name">Import GitHub Repo URL</div>
                <div className="repo-btn-sub">Fetch Public Git Repository</div>
              </div>
            </button>

            <button
              className={`repo-selector-btn ${activeMode === 'zip' ? 'active' : ''}`}
              onClick={() => handleModeSwitch('zip')}
            >
              <Upload size={16} />
              <div>
                <div className="repo-btn-name">Upload Repository (.zip)</div>
                <div className="repo-btn-sub">Unpack & Audit Local Zip</div>
              </div>
            </button>

            <button
              className={`repo-selector-btn ${activeMode === 'custom' ? 'active' : ''}`}
              onClick={() => handleModeSwitch('custom')}
            >
              <FileCode size={16} />
              <div>
                <div className="repo-btn-name">Paste Code Snippet</div>
                <div className="repo-btn-sub">Instant Multi-Language Scan</div>
              </div>
            </button>
          </div>
        </div>

        {selectedRepo.files.length > 0 && (
          <div className="sidebar-section">
            <label className="sidebar-label">Repository Files ({selectedRepo.files.length}):</label>
            <div className="file-tree">
              {selectedRepo.files.map(file => {
                const fileFindingsCount = report.findings.filter(f => f.filePath === file.path).length;
                return (
                  <button
                    key={file.path}
                    className={`file-item ${activeFile?.path === file.path ? 'active' : ''}`}
                    onClick={() => {
                      setActiveFile(file);
                      onSelectFinding(null);
                    }}
                  >
                    <FileCode size={16} />
                    <span className="file-name">{file.name}</span>
                    {fileFindingsCount > 0 && (
                      <span className="file-finding-badge">{fileFindingsCount}</span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>
        )}

        <div className="sidebar-section">
          <label className="sidebar-label">
            Detected Vulnerabilities ({report.findings.length}):
          </label>
          <div className="sidebar-findings-list">
            {report.findings.length === 0 ? (
              <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', padding: '0.5rem 0' }}>
                No vulnerabilities detected yet. Import a URL, upload a .zip, or paste a code snippet above to begin auditing.
              </div>
            ) : (
              report.findings.map(finding => (
                <div
                  key={finding.id}
                  className={`finding-card-item ${selectedFinding?.id === finding.id ? 'active' : ''}`}
                  onClick={() => handleSelectFinding(finding)}
                >
                  <div className="finding-card-header">
                    <span className={`severity-badge ${finding.severity.toLowerCase()}`}>
                      {finding.severity}
                    </span>
                    <span className="finding-line">Line {finding.lineNumber}</span>
                  </div>
                  <div className="finding-card-title">{finding.title}</div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Main Workspace: Code Viewer + Remediation Panel */}
      <div className="analyzer-main">
        {activeMode === 'zip' ? (
          <div className="custom-code-container" style={{ padding: '2rem', textAlign: 'center', justifyContent: 'center', alignItems: 'center' }}>
            <FolderUp size={48} style={{ color: 'var(--color-primary)', marginBottom: '1rem' }} />
            <h2>Upload & Audit Local Repository (.zip)</h2>
            <p style={{ color: 'var(--text-secondary)', margin: '0.5rem 0 1.5rem' }}>
              Upload any zip archive containing Python, TypeScript, JavaScript, SQL, or Dockerfile code. ARIES will unpack and scan every file automatically.
            </p>
            <label className="scan-trigger-btn" style={{ cursor: 'pointer', display: 'inline-flex' }}>
              <Upload size={18} /> Select .ZIP Archive
              <input type="file" accept=".zip" onChange={handleZipUpload} style={{ display: 'none' }} />
            </label>
            {uploadStatus && <div style={{ marginTop: '1rem', color: 'var(--color-primary)', fontWeight: 600 }}>{uploadStatus}</div>}
          </div>
        ) : activeMode === 'url' ? (
          <div className="custom-code-container" style={{ padding: '2rem', textAlign: 'center', justifyContent: 'center', alignItems: 'center' }}>
            <LinkIcon size={48} style={{ color: 'var(--color-primary)', marginBottom: '1rem' }} />
            <h2>Import Public GitHub Repository</h2>
            <p style={{ color: 'var(--text-secondary)', margin: '0.5rem 0 1.5rem' }}>
              Enter any public GitHub repository link (e.g. <code>https://github.com/digininja/DVWA</code>) to automatically pull and run security analysis.
            </p>
            <div style={{ display: 'flex', gap: '0.75rem', maxWidth: '600px', width: '100%' }}>
              <input
                type="text"
                className="api-key-input"
                style={{ flex: 1, padding: '0.75rem', borderRadius: '6px', border: '1px solid var(--border-color)', background: 'var(--bg-dark)', width: 'auto' }}
                placeholder="https://github.com/owner/repository..."
                value={repoUrl}
                onChange={e => setRepoUrl(e.target.value)}
              />
              <button className="scan-trigger-btn" onClick={handleFetchGitHubRepo} disabled={isFetchingUrl}>
                <RefreshCw size={16} className={isFetchingUrl ? 'spin' : ''} />
                {isFetchingUrl ? 'Fetching...' : 'Fetch & Scan'}
              </button>
            </div>
            {uploadStatus && <div style={{ marginTop: '1rem', color: 'var(--color-primary)', fontWeight: 600 }}>{uploadStatus}</div>}
          </div>
        ) : activeMode === 'custom' ? (
          <div className="custom-code-container">
            <div className="code-editor-header" style={{ flexShrink: 0, position: 'sticky', top: 0, zIndex: 10 }}>
              <div style={{ fontWeight: 600, fontSize: '0.875rem', color: 'var(--text-primary)' }}>
                Paste Source Code for Instant SAST Audit
              </div>
              <button className="scan-trigger-btn" onClick={async () => {
                await onRunCustomScan();
                setActiveMode('preset');
              }} style={{ background: 'linear-gradient(135deg, #38bdf8, #2563eb)', color: '#ffffff', fontWeight: 700, padding: '0.5rem 1.25rem' }}>
                <Zap size={16} /> Analyze Snippet
              </button>
            </div>
            <div style={{ display: 'flex', flex: 1, minHeight: 0, backgroundColor: 'var(--bg-dark)', fontFamily: 'var(--font-mono)', overflow: 'hidden' }}>
              {/* Line Numbers Gutter */}
              <div
                ref={gutterRef}
                style={{
                  padding: '0.85rem 0.75rem',
                  backgroundColor: 'var(--bg-card)',
                  color: 'var(--text-muted)',
                  textAlign: 'right',
                  userSelect: 'none',
                  fontSize: '0.85rem',
                  borderRight: '1px solid var(--border-color)',
                  lineHeight: '1.5',
                  flexShrink: 0,
                  overflowY: 'hidden'
                }}
              >
                {customCode.split('\n').map((_, idx) => (
                  <div key={idx}>{idx + 1}</div>
                ))}
              </div>
              {/* Code Textarea */}
              <textarea
                className="custom-code-textarea"
                value={customCode}
                onChange={e => setCustomCode(e.target.value)}
                onScroll={e => {
                  if (gutterRef.current) {
                    gutterRef.current.scrollTop = e.currentTarget.scrollTop;
                  }
                }}
                placeholder="Paste Python, TypeScript, SQL, or Node.js code here..."
              />
            </div>
          </div>
        ) : activeFile ? (
          <div className="code-viewer-container">
            <div className="code-editor-header">
              <div className="file-path-breadcrumbs">
                <FileCode size={16} />
                <code>{activeFile.path}</code>
              </div>
              <div className="lang-tag">{activeFile.language.toUpperCase()}</div>
            </div>

            <div className="code-display">
              {activeFile.content.split('\n').map((line, idx) => {
                const lineNum = idx + 1;
                const findingOnLine = report.findings.find(
                  f => f.filePath === activeFile.path && f.lineNumber === lineNum
                );
                const isSelected = selectedFinding?.lineNumber === lineNum && selectedFinding?.filePath === activeFile.path;

                return (
                  <div
                    key={idx}
                    className={`code-line ${findingOnLine ? 'has-vulnerability' : ''} ${isSelected ? 'selected' : ''}`}
                    onClick={() => findingOnLine && onSelectFinding(findingOnLine)}
                  >
                    <span className="line-num">{lineNum}</span>
                    <span className="line-text">{line}</span>
                    {findingOnLine && (
                      <span className="vuln-indicator-badge">
                        <ShieldAlert size={12} /> {findingOnLine.severity}
                      </span>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        ) : (
          <div className="no-selection-placeholder">
            <ShieldAlert size={36} />
            <p>No file loaded yet. Input a GitHub repository URL or upload a .ZIP to view file code & vulnerabilities.</p>
          </div>
        )}

        {/* Selected Finding Detail & Remediation Diff Panel */}
        {selectedFinding ? (
          <div className="finding-remediation-panel">
            <div className="remediation-header">
              <div>
                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                  <span className={`severity-badge ${selectedFinding.severity.toLowerCase()}`}>
                    {selectedFinding.severity}
                  </span>
                  <span className="ai-verified-tag" style={{ background: 'rgba(16, 185, 129, 0.15)', padding: '0.2rem 0.5rem', borderRadius: '4px', border: '1px solid var(--color-success)' }}>
                    <CheckCircle size={12} /> Validation Passed (7/7 Checks)
                  </span>
                  <span className="tag">Confidence: {selectedFinding.confidence}%</span>
                </div>
                <h2 className="remediation-title">{selectedFinding.title}</h2>
                <div className="remediation-tags">
                  <span className="tag">OWASP: {selectedFinding.owaspCategory}</span>
                  <span className="tag">CWE: {selectedFinding.cwe}</span>
                  <span className="tag">CVSS: {selectedFinding.cvssScore}</span>
                </div>
              </div>
              <button className="copy-diff-btn" onClick={() => handleCopyDiff(selectedFinding.remediation.gitDiff)}>
                {copied ? <CheckCircle size={16} /> : <Copy size={16} />}
                {copied ? 'Copied Git Patch!' : 'Copy Minimal Git Patch'}
              </button>
            </div>

            <div className="remediation-grid">
              {/* Left Box: Root Cause & Why It Matters */}
              <div className="remediation-box">
                <h4 className="box-title">Root Cause & Exploitability Analysis</h4>
                <p className="box-text"><strong>Root Cause:</strong> {selectedFinding.rootCause}</p>
                <p className="box-text secondary" style={{ marginTop: '0.5rem' }}>{selectedFinding.whyItMatters}</p>

                {/* Evidence Chain / Taint Dependency Graph */}
                {selectedFinding.evidenceChain && selectedFinding.evidenceChain.length > 0 && (
                  <div style={{ marginTop: '1rem', padding: '0.75rem', backgroundColor: 'rgba(56, 189, 248, 0.08)', borderLeft: '3px solid var(--color-primary)', borderRadius: '4px' }}>
                    <h4 style={{ fontSize: '0.8rem', color: 'var(--color-primary)', fontWeight: 700, marginBottom: '0.5rem' }}>
                      🔗 Evidence Chain (Taint Dependency Graph)
                    </h4>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                      {selectedFinding.evidenceChain.map((step, sIdx) => (
                        <div key={sIdx} style={{ fontSize: '0.78rem', fontFamily: 'var(--font-mono)', color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                          <span style={{ color: 'var(--color-primary)', fontWeight: 700 }}>Step {sIdx + 1}:</span>
                          <span>{step}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div style={{ marginTop: '1rem', padding: '0.75rem', backgroundColor: 'rgba(249, 115, 22, 0.1)', borderLeft: '3px solid var(--color-high)', borderRadius: '4px' }}>
                  <h4 style={{ fontSize: '0.8rem', color: 'var(--color-high)', fontWeight: 700, marginBottom: '0.25rem' }}>
                    ⚠️ Residual Risk Assessment
                  </h4>
                  <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                    {selectedFinding.remediation.residualRisk}
                  </p>
                </div>
              </div>

              {/* Right Box: Senior Engineer Minimal Git Diff */}
              <div className="remediation-box diff">
                <h4 className="box-title">Senior Security Engineer Patch (Minimal Git Diff)</h4>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
                  <strong>Fix Summary:</strong> {selectedFinding.remediation.fixSummary}
                </div>
                <pre className="diff-code">
                  <code>{selectedFinding.remediation.gitDiff}</code>
                </pre>
                <div style={{ marginTop: '0.5rem' }}>
                  <h5 style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Remediated Code Statement:</h5>
                  <pre className="diff-code" style={{ color: '#6ee7b7', marginTop: '0.25rem' }}>
                    <code>{selectedFinding.remediation.suggestedCode}</code>
                  </pre>
                </div>
              </div>
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
};
