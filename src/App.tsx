import React, { useState } from 'react';
import type { SecurityReport, VulnerabilityFinding, PresetRepo, PresetFile } from './types/sast';
import { SASTEngine } from './engine/sastEngine';
import { Header } from './components/Header';
import { LandingPage } from './components/LandingPage';
import { CodeAnalyzer } from './components/CodeAnalyzer';
import { RationalePage } from './components/RationalePage';

export function detectSnippetLanguage(code: string, overrideLang?: string): { language: 'python' | 'javascript' | 'typescript'; filename: string } {
  if (overrideLang === 'python') return { language: 'python', filename: 'custom_input.py' };
  if (overrideLang === 'javascript') return { language: 'javascript', filename: 'custom_input.js' };
  if (overrideLang === 'typescript') return { language: 'typescript', filename: 'custom_input.ts' };

  const isTs = /(?:interface\s+\w+|enum\s+\w+|type\s+\w+\s*=|implements\s+\w+|readonly\s+|import\s+type\s+|:\s*(?:string|number|boolean|any|void)|<[A-Z]>\s*\(|\bpublic\s+|\bprivate\s+|\bprotected\s+)/.test(code);
  if (isTs) {
    return { language: 'typescript', filename: 'custom_input.ts' };
  }

  const isPy = /(?:def\s+\w+|import\s+(?:os|sys|flask|requests|django|fastapi|pathlib)|from\s+\w+\s+import|if\s+__name__\s*==|class\s+\w+.*:|print\(|#)/.test(code);
  if (isPy) {
    return { language: 'python', filename: 'custom_input.py' };
  }

  return { language: 'javascript', filename: 'custom_input.js' };
}

const INITIAL_EMPTY_REPORT: SecurityReport = {
  timestamp: new Date().toISOString(),
  targetRepositoryName: 'No Repository Loaded',
  totalFilesScanned: 0,
  totalLinesScanned: 0,
  scanDurationMs: 0,
  findings: [],
  summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  owaspBreakdown: {}
};

const INITIAL_EMPTY_REPO: PresetRepo = {
  id: 'empty-workspace',
  name: 'No Repository Loaded',
  description: 'Upload a repository or paste code to analyze',
  files: []
};

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'home' | 'analyzer' | 'rationale'>('home');
  const [selectedRepo, setSelectedRepo] = useState<PresetRepo>(INITIAL_EMPTY_REPO);
  const [report, setReport] = useState<SecurityReport>(INITIAL_EMPTY_REPORT);
  const [selectedFinding, setSelectedFinding] = useState<VulnerabilityFinding | null>(null);
  const [customCode, setCustomCode] = useState<string>(`# Paste your code snippet here to check for vulnerabilities
import sqlite3

def find_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    sql = "SELECT * FROM users WHERE username='{}'"
    query = sql.format(username)
    cursor.execute(query)

    return cursor.fetchall()
`);

  const handleRunCustomScan = async (overrideLang?: string) => {
    if (!customCode.trim()) return;
    const detected = detectSnippetLanguage(customCode, overrideLang);
    const customFile: PresetFile = {
      name: detected.filename,
      path: detected.filename,
      language: detected.language,
      content: customCode
    };
    const customRepo: PresetRepo = {
      id: `custom-${Date.now()}`,
      name: 'Pasted Custom Snippet',
      description: 'User-provided code snippet',
      files: [customFile]
    };
    setSelectedRepo(customRepo);
    const newReport = await SASTEngine.analyzeFiles('Custom Code Snippet', [customFile]);
    setReport(newReport);
  };

  const handleResetWorkspace = () => {
    setSelectedRepo(INITIAL_EMPTY_REPO);
    setReport(INITIAL_EMPTY_REPORT);
    setSelectedFinding(null);
  };

  return (
    <div className="app-container">
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
      />

      <main className="main-content">
        {activeTab === 'home' && (
          <LandingPage
            onNavigateToAnalyzer={() => setActiveTab('analyzer')}
            onNavigateToDocs={() => setActiveTab('rationale')}
          />
        )}

        {activeTab === 'analyzer' && (
          <CodeAnalyzer
            report={report}
            selectedRepo={selectedRepo}
            selectedFinding={selectedFinding}
            onSelectFinding={finding => setSelectedFinding(finding)}
            customCode={customCode}
            setCustomCode={setCustomCode}
            onRunCustomScan={handleRunCustomScan}
            onResetWorkspace={handleResetWorkspace}
            onAnalyzeCustomFiles={async (repoName, files) => {
              const customRepo: PresetRepo = {
                id: `github-${Date.now()}`,
                name: repoName,
                description: `Fetched GitHub repository (${files.length} files)`,
                files
              };
              setSelectedRepo(customRepo);
              const newReport = await SASTEngine.analyzeFiles(repoName, files);
              setReport(newReport);
              return newReport;
            }}
          />
        )}

        {activeTab === 'rationale' && <RationalePage />}
      </main>
    </div>
  );
};

export default App;
