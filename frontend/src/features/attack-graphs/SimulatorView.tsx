import React, { useState } from 'react';
import { 
  Sliders, 
  ShieldCheck, 
  Play, 
  Check, 
  Scissors, 
  ArrowRight,
  TrendingDown,
  Info
} from 'lucide-react';
import { api } from '../../lib/api';
import { CounterfactualSimulationResult } from '../../types';

export const SimulatorView: React.FC = () => {
  const [severEdge1, setSeverEdge1] = useState(false);
  const [patchLog4j, setPatchLog4j] = useState(false);
  const [patchOutlook, setPatchOutlook] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<CounterfactualSimulationResult | null>(null);

  const handleRunSimulation = async () => {
    setLoading(true);
    try {
      const severedEdges = [];
      if (severEdge1) severedEdges.push('rel-app-to-db');

      const remediatedCves = [];
      if (patchLog4j) remediatedCves.push('CVE-2021-44228');
      if (patchOutlook) remediatedCves.push('CVE-2024-21413');

      const simResult = await api.simulateRemediation(severedEdges, remediatedCves);
      setResult(simResult);
    } catch (err: any) {
      alert(`Simulation Error: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      <div>
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <Sliders className="w-5 h-5 text-blue-400" />
          <span>Counterfactual Remediation Simulator</span>
        </h2>
        <p className="text-xs text-gray-400 mt-1">
          Perform "what-if" risk calculations. Model applying compensating controls or patching shared dependencies to calculate severed attack paths.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Mitigations Control Panel */}
        <div className="bg-[#111827] border border-gray-800 p-6 rounded-xl space-y-6 lg:col-span-1">
          <h3 className="font-semibold text-white text-sm">Select Candidate Mitigations</h3>

          <div className="space-y-4 text-xs">
            {/* Control 1: Firewall Rule */}
            <label className={`block p-3 rounded-lg border cursor-pointer transition-all ${
              severEdge1 ? 'bg-blue-600/10 border-blue-500' : 'bg-gray-900/60 border-gray-800 hover:border-gray-700'
            }`}>
              <div className="flex items-start gap-3">
                <input
                  type="checkbox"
                  checked={severEdge1}
                  onChange={(e) => setSeverEdge1(e.target.checked)}
                  className="mt-0.5 rounded text-blue-600 focus:ring-0"
                />
                <div className="space-y-1">
                  <span className="font-semibold text-white block">Micro-segment Database Ingress</span>
                  <p className="text-gray-400 text-[11px]">
                    Block port 5432 ingress between Internal App Server and Crown Jewel Database.
                  </p>
                </div>
              </div>
            </label>

            {/* Control 2: Patch Log4j */}
            <label className={`block p-3 rounded-lg border cursor-pointer transition-all ${
              patchLog4j ? 'bg-blue-600/10 border-blue-500' : 'bg-gray-900/60 border-gray-800 hover:border-gray-700'
            }`}>
              <div className="flex items-start gap-3">
                <input
                  type="checkbox"
                  checked={patchLog4j}
                  onChange={(e) => setPatchLog4j(e.target.checked)}
                  className="mt-0.5 rounded text-blue-600 focus:ring-0"
                />
                <div className="space-y-1">
                  <span className="font-semibold text-white block">Patch CVE-2021-44228 (Log4j)</span>
                  <p className="text-gray-400 text-[11px]">
                    Upgrade internal application log4j-core package to 2.15.0+.
                  </p>
                </div>
              </div>
            </label>

            {/* Control 3: Patch Outlook RCE */}
            <label className={`block p-3 rounded-lg border cursor-pointer transition-all ${
              patchOutlook ? 'bg-blue-600/10 border-blue-500' : 'bg-gray-900/60 border-gray-800 hover:border-gray-700'
            }`}>
              <div className="flex items-start gap-3">
                <input
                  type="checkbox"
                  checked={patchOutlook}
                  onChange={(e) => setPatchOutlook(e.target.checked)}
                  className="mt-0.5 rounded text-blue-600 focus:ring-0"
                />
                <div className="space-y-1">
                  <span className="font-semibold text-white block">Mitigate CVE-2024-21413 (Gateway RCE)</span>
                  <p className="text-gray-400 text-[11px]">
                    Deploy perimeter WAF rule to inspect and block malicious moniker link protocols.
                  </p>
                </div>
              </div>
            </label>
          </div>

          <button
            onClick={handleRunSimulation}
            disabled={loading}
            className="w-full py-2.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded-lg text-xs font-semibold flex items-center justify-center gap-2 shadow-lg shadow-blue-600/20"
          >
            <Play className="w-4 h-4 fill-current" />
            <span>{loading ? 'Evaluating Graph Cut-Set...' : 'Execute Counterfactual Run'}</span>
          </button>
        </div>

        {/* Results Panel */}
        <div className="bg-[#111827] border border-gray-800 p-6 rounded-xl space-y-6 lg:col-span-2">
          <h3 className="font-semibold text-white text-sm">Simulation Impact Assessment</h3>

          {!result ? (
            <div className="h-64 flex flex-col items-center justify-center text-center text-gray-500 space-y-2">
              <Sliders className="w-8 h-8 text-gray-600" />
              <p className="text-xs">Select one or more candidate controls on the left and run simulation.</p>
            </div>
          ) : (
            <div className="space-y-6">
              {/* Metrics Row */}
              <div className="grid grid-cols-3 gap-4 text-xs font-mono">
                <div className="bg-gray-900/60 p-4 rounded-xl border border-gray-800">
                  <span className="text-gray-400 font-sans block mb-1">Initial Active Paths</span>
                  <span className="text-2xl font-bold text-amber-400">{result.initial_critical_paths_count}</span>
                </div>
                <div className="bg-gray-900/60 p-4 rounded-xl border border-gray-800">
                  <span className="text-gray-400 font-sans block mb-1">Severed Paths</span>
                  <span className="text-2xl font-bold text-emerald-400">{result.severed_paths_count}</span>
                </div>
                <div className="bg-gray-900/60 p-4 rounded-xl border border-gray-800">
                  <span className="text-gray-400 font-sans block mb-1">Residual Risk Paths</span>
                  <span className={`text-2xl font-bold ${result.residual_critical_paths_count === 0 ? 'text-emerald-400' : 'text-red-400'}`}>
                    {result.residual_critical_paths_count}
                  </span>
                </div>
              </div>

              {/* Status Outcome Banner */}
              <div className={`p-4 rounded-xl border text-xs flex items-start gap-3 ${
                result.residual_critical_paths_count === 0
                  ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                  : 'bg-amber-500/10 border-amber-500/30 text-amber-300'
              }`}>
                <ShieldCheck className="w-5 h-5 shrink-0 mt-0.5" />
                <div className="space-y-1">
                  <span className="font-bold block">
                    {result.residual_critical_paths_count === 0 
                      ? 'Crown Jewels Fully Disconnected from Attack Chain' 
                      : 'Partial Mitigation: Residual Attack Paths Remain'}
                  </span>
                  <p className="text-[11px] opacity-90">{result.recommendations.join(' ')}</p>
                </div>
              </div>

              {/* Severed Paths List */}
              {result.severed_path_details.length > 0 && (
                <div className="space-y-2">
                  <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider block">
                    Severed Attack Chain Sequences ({result.severed_path_details.length})
                  </span>
                  <div className="space-y-2 font-mono text-xs">
                    {result.severed_path_details.map((p, idx) => (
                      <div key={idx} className="bg-gray-900 p-3 rounded-lg border border-gray-800 flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Scissors className="w-4 h-4 text-emerald-400" />
                          <span className="text-white">{p.path_id}: {p.entry_asset}</span>
                          <ArrowRight className="w-3.5 h-3.5 text-gray-500" />
                          <span className="text-emerald-400">{p.target_asset}</span>
                        </div>
                        <span className="text-[10px] bg-emerald-500/20 text-emerald-400 px-2 py-0.5 rounded">
                          SEVERED
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
