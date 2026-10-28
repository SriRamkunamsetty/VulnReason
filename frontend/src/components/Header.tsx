import React from 'react';
import { Shield, Database, Radio, User } from 'lucide-react';

interface HeaderProps {
  dbConnected: boolean;
}

export const Header: React.FC<HeaderProps> = ({ dbConnected }) => {
  return (
    <header className="h-16 bg-[#111827] border-b border-gray-800 px-6 flex items-center justify-between sticky top-0 z-40">
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-lg bg-blue-600/20 border border-blue-500/40 flex items-center justify-center">
          <Shield className="w-6 h-6 text-blue-400" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="font-bold text-lg tracking-tight text-white">VulnReason</h1>
            <span className="text-xs bg-blue-500/10 text-blue-400 border border-blue-500/30 px-2 py-0.5 rounded font-mono">
              v1.0.0-prod
            </span>
          </div>
          <p className="text-xs text-gray-400">Evidence-Driven Vulnerability Triage & Attack-Path Reasoning</p>
        </div>
      </div>

      <div className="flex items-center gap-4">
        {/* Intelligence Status Pill */}
        <div className="flex items-center gap-2 bg-gray-900/80 border border-gray-800 px-3 py-1.5 rounded-full text-xs">
          <Radio className="w-3.5 h-3.5 text-emerald-400 animate-pulse" />
          <span className="text-gray-300">CISA KEV & EPSS: <strong className="text-emerald-400">Live</strong></span>
        </div>

        {/* Database Status */}
        <div className="flex items-center gap-2 bg-gray-900/80 border border-gray-800 px-3 py-1.5 rounded-full text-xs">
          <Database className={`w-3.5 h-3.5 ${dbConnected ? 'text-emerald-400' : 'text-amber-400'}`} />
          <span className="text-gray-300">DB: {dbConnected ? 'PostgreSQL/Async' : 'Connecting...'}</span>
        </div>

        {/* Organization / Tenant */}
        <div className="flex items-center gap-2 bg-gray-900/80 border border-gray-800 px-3 py-1.5 rounded-full text-xs">
          <User className="w-3.5 h-3.5 text-blue-400" />
          <span className="text-gray-300">Tenant: <strong className="text-white">Alignerr-Demo</strong></span>
        </div>
      </div>
    </header>
  );
};
