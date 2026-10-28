import React, { useState } from 'react';
import { 
  GitFork, 
  CheckCircle, 
  AlertTriangle, 
  ArrowRight, 
  ShieldCheck, 
  Server, 
  Database,
  Lock,
  Layers
} from 'lucide-react';
import { AttackPath } from '../../types';

interface AttackGraphViewProps {
  attackPaths: AttackPath[];
}

export const AttackGraphView: React.FC<AttackGraphViewProps> = ({ attackPaths }) => {
  const [selectedPath, setSelectedPath] = useState<AttackPath | null>(
    attackPaths.length > 0 ? attackPaths[0] : null
  );

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      <div>
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <GitFork className="w-5 h-5 text-amber-400" />
          <span>Evidence-Backed Attack Paths</span>
        </h2>
        <p className="text-xs text-gray-400 mt-1">
          Bounded path analysis from perimeter entry points to high-value assets. Never hallucinates unproven network hops.
        </p>
      </div>

      {attackPaths.length === 0 ? (
        <div className="bg-[#111827] border border-gray-800 p-12 rounded-xl text-center space-y-3">
          <ShieldCheck className="w-10 h-10 text-emerald-400 mx-auto" />
          <h3 className="font-semibold text-white">No Reachable Critical Paths Detected</h3>
          <p className="text-xs text-gray-400 max-w-md mx-auto">
            All high-impact crown jewel assets are properly isolated without verified traversal chains from exposed perimeter servers.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Path Selection Column */}
          <div className="space-y-3 lg:col-span-1">
            <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider block">
              Discovered Attack Paths ({attackPaths.length})
            </span>
            {attackPaths.map((path) => {
              const isSelected = selectedPath?.path_id === path.path_id;
              const isVerified = path.feasibility_tier === 'VERIFIED_CHAIN';
              return (
                <div
                  key={path.path_id}
                  onClick={() => setSelectedPath(path)}
                  className={`p-4 rounded-xl border cursor-pointer transition-all ${
                    isSelected
                      ? 'bg-blue-600/10 border-blue-500/50 shadow-lg'
                      : 'bg-[#111827] border-gray-800 hover:border-gray-700'
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-mono text-xs font-bold text-white">{path.path_id}</span>
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-bold ${
                      isVerified 
                        ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' 
                        : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                    }`}>
                      {path.feasibility_tier.replace('_', ' ')}
                    </span>
                  </div>

                  <div className="text-xs text-gray-300 flex items-center gap-1.5 font-mono mb-2">
                    <span>{path.entry_asset}</span>
                    <ArrowRight className="w-3.5 h-3.5 text-gray-500" />
                    <span className="text-red-400 font-bold">{path.target_asset}</span>
                  </div>

                  <div className="text-[11px] text-gray-500 flex justify-between pt-2 border-t border-gray-800/60">
                    <span>Hops: {path.path_length}</span>
                    <span>Verified Edge Ratio: {(path.verified_edge_ratio * 100).toFixed(0)}%</span>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Path Detail & Topology Inspection */}
          {selectedPath && (
            <div className="bg-[#111827] border border-gray-800 p-6 rounded-xl space-y-6 lg:col-span-2">
              <div className="flex items-center justify-between border-b border-gray-800 pb-4">
                <div>
                  <h3 className="font-bold text-white text-base">Path Breakdown: {selectedPath.path_id}</h3>
                  <p className="text-xs text-gray-400 mt-0.5">
                    Target: <strong className="text-red-400">{selectedPath.target_asset}</strong> ({selectedPath.target_criticality})
                  </p>
                </div>
                <div className="text-right">
                  <span className="text-xs text-gray-400 block">Edge Confidence</span>
                  <span className="font-mono font-bold text-emerald-400 text-sm">
                    {(selectedPath.verified_edge_ratio * 100).toFixed(0)}% Confirmed
                  </span>
                </div>
              </div>

              {/* Visual Hop Progression */}
              <div className="space-y-4">
                <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider block">
                  Topological Step Sequence
                </span>
                <div className="space-y-3 font-mono text-xs">
                  {selectedPath.hops.map((hop, idx) => (
                    <div 
                      key={idx}
                      className="bg-gray-900/80 border border-gray-800 p-4 rounded-xl flex items-center justify-between gap-4"
                    >
                      <div className="flex items-center gap-3">
                        <div className="w-7 h-7 rounded-full bg-blue-600/20 text-blue-400 border border-blue-500/30 flex items-center justify-center font-bold text-xs shrink-0">
                          {hop.step_number}
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="text-white font-bold">{hop.source_hostname}</span>
                            <ArrowRight className="w-3.5 h-3.5 text-gray-500" />
                            <span className="text-white font-bold">{hop.target_hostname}</span>
                          </div>
                          <div className="text-[11px] text-gray-400 mt-1 font-sans">
                            Relationship: <span className="text-blue-400 font-mono">{hop.relationship_type}</span> {hop.port && `(Port ${hop.port})`}
                          </div>
                        </div>
                      </div>

                      <div className="text-right shrink-0">
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                          hop.state === 'VERIFIED'
                            ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                            : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                        }`}>
                          {hop.state}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Accessible Alternative: Full Table View */}
              <div className="pt-4 border-t border-gray-800">
                <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider block mb-2">
                  Accessible Path Audit Table (WCAG Screen-Reader Equivalent)
                </span>
                <table className="w-full text-left text-xs border border-gray-800 rounded overflow-hidden">
                  <thead className="bg-gray-900 text-gray-400 font-semibold">
                    <tr>
                      <th className="p-2.5">Step</th>
                      <th className="p-2.5">From Asset</th>
                      <th className="p-2.5">To Asset</th>
                      <th className="p-2.5">Mechanism</th>
                      <th className="p-2.5">Preconditions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-800 font-mono">
                    {selectedPath.hops.map((hop) => (
                      <tr key={hop.step_number} className="text-gray-300">
                        <td className="p-2.5">{hop.step_number}</td>
                        <td className="p-2.5 text-blue-400">{hop.source_hostname}</td>
                        <td className="p-2.5 text-amber-400">{hop.target_hostname}</td>
                        <td className="p-2.5">{hop.relationship_type}</td>
                        <td className="p-2.5 font-sans text-gray-400">{hop.prerequisites.join('; ')}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
