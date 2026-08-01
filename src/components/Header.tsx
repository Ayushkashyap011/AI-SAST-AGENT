import React from 'react';
import { ShieldAlert, Cpu, FileText, Home } from 'lucide-react';

interface HeaderProps {
  activeTab: 'home' | 'analyzer' | 'rationale';
  setActiveTab: (tab: 'home' | 'analyzer' | 'rationale') => void;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setActiveTab
}) => {
  return (
    <header className="app-header">
      <div className="header-brand" onClick={() => setActiveTab('home')} style={{ cursor: 'pointer' }}>
        <div className="brand-icon-wrapper">
          <ShieldAlert className="brand-icon" />
        </div>
        <div>
          <h1 className="brand-title">ARIES SAST Agent</h1>
          <p className="brand-subtitle">Autonomous Security Code Auditor & Patch Synthesizer</p>
        </div>
      </div>

      <nav className="header-nav">
        <button
          className={`nav-btn ${activeTab === 'home' ? 'active' : ''}`}
          onClick={() => setActiveTab('home')}
        >
          <Home size={16} />
          Home
        </button>
        <button
          className={`nav-btn ${activeTab === 'analyzer' ? 'active' : ''}`}
          onClick={() => setActiveTab('analyzer')}
        >
          <Cpu size={16} />
          Check Vulnerabilities
        </button>
        <button
          className={`nav-btn ${activeTab === 'rationale' ? 'active' : ''}`}
          onClick={() => setActiveTab('rationale')}
        >
          <FileText size={16} />
          Documentation
        </button>
      </nav>
    </header>
  );
};
