import React from 'react';
import { ShieldCheck, FileText, ArrowRight, Sparkles } from 'lucide-react';

interface LandingPageProps {
  onNavigateToAnalyzer: () => void;
  onNavigateToDocs: () => void;
}

export const LandingPage: React.FC<LandingPageProps> = ({
  onNavigateToAnalyzer,
  onNavigateToDocs
}) => {
  return (
    <div className="landing-container">
      {/* Hero Header */}
      <div className="hero-section">
        <div className="hero-badge">
          <Sparkles size={14} className="badge-icon" />
          <span>Next-Generation AI Security Auditor</span>
        </div>
        <h1 className="hero-title">
          ARIES <span className="title-gradient">SAST ENGINE</span>
        </h1>
        <p className="hero-subtitle">
          Autonomous static application security testing. Deep taint dependency graphing, zero false-positive context suppression, and PR-ready senior engineer code patches.
        </p>
      </div>

      {/* Main 2 Card Grid matching hand-drawn wireframe */}
      <div className="wireframe-cards-grid">
        {/* Card 1: Check Your Vulnerabilities */}
        <div className="hero-card primary-card" onClick={onNavigateToAnalyzer}>
          <div className="card-top-icon">
            <ShieldCheck size={42} />
          </div>
          <h2 className="card-heading">Check Your Vulnerabilities</h2>
          <p className="card-description">
            Audit any codebase instantly. Support for GitHub repository links, local ZIP archives, and raw code snippet scanning.
          </p>
          <div className="card-action-btn primary-btn">
            <span>Launch Code Auditor</span>
            <ArrowRight size={18} />
          </div>
        </div>

        {/* Card 2: Documentation */}
        <div className="hero-card secondary-card" onClick={onNavigateToDocs}>
          <div className="card-top-icon">
            <FileText size={42} />
          </div>
          <h2 className="card-heading">Documentation</h2>
          <p className="card-description">
            Explore how our agent works. Deep dive into the 4-pass taint graph engine, false positive filters, and 30-day architecture roadmap.
          </p>
          <div className="card-action-btn secondary-btn">
            <span>Read How Agent Works</span>
            <ArrowRight size={18} />
          </div>
        </div>
      </div>
    </div>
  );
};
