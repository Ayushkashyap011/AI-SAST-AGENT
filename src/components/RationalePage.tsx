import React from 'react';
import { Cpu, XCircle, Target, Download, Rocket } from 'lucide-react';

export const RationalePage: React.FC = () => {
  return (
    <div className="rationale-container">
      <div className="rationale-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem', marginBottom: '2rem' }}>
        <div>
          <h1 className="rationale-title">ARIES SAST Agent: Design Architecture & Rationale</h1>
          <p className="rationale-subtitle" style={{ maxWidth: '800px' }}>
            Security teams cannot inspect code fast enough. ARIES pairs deterministic interprocedural taint analysis with a Senior Security Engineer AI Patch Synthesizer to eliminate false positives and generate production-ready Git patches.
          </p>
        </div>
        <a
          href="/ARIES_SAST_Agent_Design_Rationale.pdf"
          download="ARIES_SAST_Agent_Design_Rationale.pdf"
          className="scan-trigger-btn"
          style={{
            background: 'linear-gradient(135deg, #38bdf8, #2563eb)',
            color: '#ffffff',
            fontWeight: 700,
            padding: '0.65rem 1.25rem',
            borderRadius: '8px',
            textDecoration: 'none',
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.5rem'
          }}
        >
          <Download size={18} /> Download Executive PDF
        </a>
      </div>

      <div className="rationale-grid">
        {/* Card 1: Technical Architecture & Design Decisions */}
        <div className="rationale-card">
          <div className="card-icon"><Cpu size={24} /></div>
          <h3>1. Technical Architecture & Design Decisions</h3>
          <p>
            Rather than relying solely on LLMs (which hallucinate line numbers and hit context limits) or rigid legacy pattern scanners (which trigger massive false positives), ARIES implements a hybrid multi-pass architecture:
          </p>
          <ul>
            <li><strong>Sink-Driven Classification:</strong> String formatting is treated as a transformation, NOT a vulnerability. A vulnerability ONLY exists when untrusted input flows into a verified execution sink (e.g. <code>cursor.execute()</code>, <code>mysql2.query()</code>, <code>subprocess.run()</code>, <code>render_template_string()</code>).</li>
            <li><strong>Interprocedural AST Scope Engine:</strong> Implements brace-counting scope parsing to assign unique scope identifiers (<code>anon_func_L42</code>) to anonymous route handlers (Express <code>app.get</code>, <code>router.post</code>) and trace data flows across helper wrappers.</li>
            <li><strong>Recursive Repository Collector:</strong> Traverses multi-folder repositories while automatically filtering vendor folders (<code>node_modules</code>, <code>dist</code>, <code>build</code>), minified files, lockfiles, and test specs.</li>
            <li><strong>Snippet Language Detection:</strong> Syntax heuristics evaluate pasted code snippets (TypeScript, Python, JavaScript) to assign virtual filenames with manual dropdown overrides.</li>
          </ul>
        </div>

        {/* Card 2: What We Deliberately Rejected */}
        <div className="rationale-card">
          <div className="card-icon"><XCircle size={24} /></div>
          <h3>2. Deliberate Trade-Offs & Rejections</h3>
          <p>
            To deliver an enterprise-grade auditor that security engineers can trust, we consciously rejected:
          </p>
          <ul>
            <li><strong>Pure LLM-Only Code Auditing:</strong> Passing raw repository files directly to an LLM was rejected due to context window limits, non-deterministic line localization, latency, and cost. LLM execution is restricted to Pass 4 (AI validation and patch synthesis).</li>
            <li><strong>Unconditioned Keyword Sinks:</strong> Flagging generic framework methods such as <code>res.send()</code> without inspecting payload contents was rejected. ARIES enforces HTML tag detection (<code>&lt;h1&gt;...&lt;/h1&gt;</code>) before reporting XSS findings.</li>
            <li><strong>Static File Sampling Caps:</strong> Capping repo scans to 100 files was rejected. The engine recursively processes all application source files across large multi-folder repositories (NodeGoat, OWASP Juice Shop, DVNA).</li>
          </ul>
        </div>

        {/* Card 3: False Positive & Edge-Case Engineering */}
        <div className="rationale-card">
          <div className="card-icon"><Target size={24} /></div>
          <h3>3. False Positive & Edge-Case Engineering</h3>
          <p>
            False positives ruin developer trust. ARIES mitigates them through precise context guards:
          </p>
          <ul>
            <li><strong>DOM Navigation Guard:</strong> Browser navigation calls (<code>window.open()</code>) are guarded against misclassification as Path Traversal filesystem sinks.</li>
            <li><strong>Static URL SSRF Suppression:</strong> Compile-time constant URLs (<code>requests.get("https://api.github.com")</code>) are excluded from SSRF findings.</li>
            <li><strong>Line Proximity Deduplication:</strong> Merges duplicate taint graph and static pattern findings within ±4 lines of the same file and CWE into a single alert with a unified evidence chain.</li>
            <li><strong>Non-Blocking Parser Resilience:</strong> Unparseable files log errors and resume scanning remaining files without aborting execution.</li>
          </ul>
        </div>

        {/* Card 4: 30-Day Engineering Roadmap */}
        <div className="rationale-card highlight">
          <div className="card-icon"><Rocket size={24} /></div>
          <h3>4. 30-Day Engineering Roadmap</h3>
          <p>
            Here is the exact technical roadmap to take ARIES to enterprise production:
          </p>
          <ul>
            <li><strong>1. WebAssembly Concrete Syntax Tree (CST) Parsers:</strong> Integrate Tree-Sitter WebAssembly bindings for full CST parsing across C++, Go, Rust, Java, and Python.</li>
            <li><strong>2. Cross-File Import Taint Propagation:</strong> Expand interprocedural tracking across module boundaries to resolve imported helper functions (e.g. <code>from db.utils import execute_raw</code>) across multi-file repositories.</li>
            <li><strong>3. CI/CD Pipeline Integration & IDE Extensions:</strong> Package the engine as a GitHub Action and VS Code extension to provide inline PR review comments and IDE diagnostic highlighting.</li>
            <li><strong>4. Patched Code Sandbox Execution:</strong> Execute automated unit and regression tests inside isolated WebAssembly micro-containers to verify patch correctness prior to merge.</li>
          </ul>
        </div>
      </div>
    </div>
  );
};
