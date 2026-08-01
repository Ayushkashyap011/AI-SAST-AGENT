import React from 'react';
import { Cpu, XCircle, Lightbulb, Target } from 'lucide-react';

export const RationalePage: React.FC = () => {
  return (
    <div className="rationale-container">
      <div className="rationale-header">
        <h1 className="rationale-title">Architectural Rationale & Thought Process</h1>
        <p className="rationale-subtitle">
          One-page evaluation breakdown: Choices made, deliberate trade-offs, false positive elimination strategies, and future vision.
        </p>
      </div>

      <div className="rationale-grid">
        {/* Card 1: What We Built & Why */}
        <div className="rationale-card">
          <div className="card-icon"><Cpu size={24} /></div>
          <h3>1. Core Architecture: Multi-Pass Hybrid SAST Engine</h3>
          <p>
            Rather than relying solely on LLMs (which are prone to hallucinating line numbers and high latency on large repos) or rigid legacy regex parsers, we designed a <strong>3-Pass Dynamic Pipeline</strong>:
          </p>
          <ul>
            <li><strong>Pass 1 (AST/Syntax Heuristics):</strong> Instantaneous pattern parsing for high-risk AST nodes (SQL formatting strings, command execution, un-sanitized DOM sinks, hardcoded secrets).</li>
            <li><strong>Pass 2 (Contextual False Positive Suppression):</strong> Evaluates local scope (e.g. distinguishing comments from code, detecting sanitizer calls like <code>DOMPurify.sanitize</code> or parameterized <code>?</code> query bindings).</li>
            <li><strong>Pass 3 (AI Reasoner & Patch Synthesizer):</strong> Uses Gemini AI to synthesize exact contextual diffs, explain root causes, and score CVSS severity without manual intervention.</li>
          </ul>
        </div>

        {/* Card 2: What We Deliberately Rejected */}
        <div className="rationale-card">
          <div className="card-icon"><XCircle size={24} /></div>
          <h3>2. Deliberate Trade-offs & Rejections</h3>
          <p>
            To deliver a production-ready product evaluated in minutes on Monday morning, we consciously rejected:
          </p>
          <ul>
            <li><strong>Thin Wrapper around Off-The-Shelf CLI Scanners:</strong> Running standard tools like Semgrep or Bandit wrapped in a UI scores zero in novelty and flexibility. We built our execution loop from scratch.</li>
            <li><strong>Brittle Heavy AST Compilation for Multi-Language:</strong> Parsing full C/C++ or Rust ASTs in browser JavaScript degrades performance. We prioritized fast, highly-accurate polyglot regex-AST matching for high-velocity languages (Python, TypeScript, JavaScript, SQL).</li>
            <li><strong>Raw Prompt-Only Scans:</strong> Sending entire 100,000-line codebases into LLM context windows causes context truncation, missing fine-grained vulnerabilities, and massive costs.</li>
          </ul>
        </div>

        {/* Card 3: Handling False Positives & Failures */}
        <div className="rationale-card">
          <div className="card-icon"><Target size={24} /></div>
          <h3>3. Eliminating False Positives & Graceful Fallbacks</h3>
          <p>
            False positives ruin developer trust. Aegis handles them through:
          </p>
          <ul>
            <li><strong>Heuristic Context Guards:</strong> Stripping code comments, docstrings, unit test mock data (e.g. <code>do_not_flag</code> markers), and checking for upstream authorization guards before flagging IDOR.</li>
            <li><strong>Graceful AI Fallback:</strong> If network connectivity or API key quotas fail, the engine falls back seamlessly to offline heuristic evaluation without breaking the user workflow.</li>
            <li><strong>Environment Isolation:</strong> Zero credentials in code; configuration driven purely by standard environment variables.</li>
          </ul>
        </div>

        {/* Card 4: Roadmap & Next Steps */}
        <div className="rationale-card highlight">
          <div className="card-icon"><Lightbulb size={24} /></div>
          <h3>4. What We’d Build With Another Month</h3>
          <ul>
            <li><strong>Taint Tracking & Interprocedural Control Flow Graphs (CFG):</strong> Trace user inputs across multiple microservice network boundaries (e.g. API Gateway &rarr; Auth &rarr; Database worker).</li>
            <li><strong>Automated Pull Request Bot & IDE Sidecar:</strong> Automatically post zero-click git commits with verified patches into GitHub Actions pipelines.</li>
            <li><strong>Custom Rule Studio:</strong> Allow security teams to define domain-specific vulnerability rules in plain natural language or YAML within seconds.</li>
          </ul>
        </div>
      </div>
    </div>
  );
};
