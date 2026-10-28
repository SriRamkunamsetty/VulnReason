import React from 'react';
import { 
  LayoutDashboard, 
  ShieldAlert, 
  GitFork, 
  Sliders, 
  Cpu, 
  Award, 
  CheckCircle2 
} from 'lucide-react';

export type TabType = 'dashboard' | 'findings' | 'graph' | 'simulator' | 'evaluation' | 'remediation';

interface SidebarProps {
  activeTab: TabType;
  setActiveTab: (tab: TabType) => void;
  p0Count: number;
  pathCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({ 
  activeTab, 
  setActiveTab, 
  p0Count, 
  pathCount 
}) => {
  const navItems = [
    { id: 'dashboard', label: 'SOC Dashboard', icon: LayoutDashboard },
    { id: 'findings', label: 'Contextual Triage', icon: ShieldAlert, badge: p0Count > 0 ? `${p0Count} P0` : undefined, badgeColor: 'bg-red-500/20 text-red-400 border border-red-500/40' },
    { id: 'graph', label: 'Attack Graph Paths', icon: GitFork, badge: pathCount > 0 ? `${pathCount} Paths` : undefined, badgeColor: 'bg-amber-500/20 text-amber-400 border border-amber-500/40' },
    { id: 'simulator', label: 'Counterfactual Simulator', icon: Sliders },
    { id: 'remediation', label: 'Remediation & Proof', icon: CheckCircle2 },
    { id: 'evaluation', label: 'VR-Bench Evaluator', icon: Award, badge: '5 Baselines', badgeColor: 'bg-purple-500/20 text-purple-400 border border-purple-500/40' },
  ];

  return (
    <aside className="w-64 bg-[#0E131F] border-r border-gray-800 flex flex-col justify-between shrink-0 h-[calc(100vh-4rem)]">
      <div className="p-4 space-y-1">
        <div className="px-3 py-2 text-xs font-semibold text-gray-400 uppercase tracking-wider">
          Core Workflows
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id as TabType)}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                isActive
                  ? 'bg-blue-600/15 text-blue-400 border border-blue-500/30'
                  : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/40'
              }`}
            >
              <div className="flex items-center gap-3">
                <Icon className={`w-4 h-4 ${isActive ? 'text-blue-400' : 'text-gray-400'}`} />
                <span>{item.label}</span>
              </div>
              {item.badge && (
                <span className={`text-[11px] font-mono px-2 py-0.5 rounded-full ${item.badgeColor}`}>
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      <div className="p-4 border-t border-gray-800/60 bg-gray-950/40">
        <div className="text-xs text-gray-400 space-y-1">
          <p className="font-semibold text-gray-300">Alignerr Evaluation Suite</p>
          <p className="text-[11px] text-gray-500">Separates deterministic security proof from LLM inference.</p>
        </div>
      </div>
    </aside>
  );
};
