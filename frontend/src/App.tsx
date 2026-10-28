import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { Sidebar, TabType } from './components/Sidebar';
import { DashboardView } from './features/dashboard/DashboardView';
import { FindingsView } from './features/findings/FindingsView';
import { AttackGraphView } from './features/attack-graphs/AttackGraphView';
import { SimulatorView } from './features/attack-graphs/SimulatorView';
import { BenchmarkView } from './features/evaluations/BenchmarkView';
import { RemediationView } from './features/remediation/RemediationView';
import { api } from './lib/api';
import { Finding, AttackPath } from './types';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabType>('dashboard');
  const [dbConnected, setDbConnected] = useState(false);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [attackPaths, setAttackPaths] = useState<AttackPath[]>([]);
  const [loading, setLoading] = useState(true);

  const loadData = async () => {
    try {
      const health = await api.checkHealth();
      setDbConnected(health.database_connected);

      const [findingsData, pathsData] = await Promise.all([
        api.getFindings(),
        api.getAttackPaths()
      ]);
      setFindings(findingsData);
      setAttackPaths(pathsData);
    } catch (err) {
      console.error("API Fetch Error:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const p0Count = findings.filter(f => f.contextual_priority === 'P0_URGENT').length;

  return (
    <div className="min-h-screen bg-[#0B0F19] text-gray-100 flex flex-col font-sans">
      <Header dbConnected={dbConnected} />
      
      <div className="flex flex-1 overflow-hidden">
        <Sidebar 
          activeTab={activeTab} 
          setActiveTab={setActiveTab} 
          p0Count={p0Count}
          pathCount={attackPaths.length}
        />

        <main className="flex-1 overflow-y-auto">
          {loading ? (
            <div className="flex items-center justify-center h-full text-xs text-gray-500 font-mono">
              Loading VulnReason Telemetry...
            </div>
          ) : (
            <>
              {activeTab === 'dashboard' && (
                <DashboardView 
                  findings={findings} 
                  attackPaths={attackPaths} 
                  onNavigate={setActiveTab} 
                />
              )}
              {activeTab === 'findings' && (
                <FindingsView 
                  findings={findings} 
                  onRefresh={loadData} 
                />
              )}
              {activeTab === 'graph' && (
                <AttackGraphView attackPaths={attackPaths} />
              )}
              {activeTab === 'simulator' && (
                <SimulatorView />
              )}
              {activeTab === 'remediation' && (
                <RemediationView />
              )}
              {activeTab === 'evaluation' && (
                <BenchmarkView />
              )}
            </>
          )}
        </main>
      </div>
    </div>
  );
};

export default App;
