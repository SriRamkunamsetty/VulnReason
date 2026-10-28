import React, { useState } from 'react';
import { 
  Award, 
  Play, 
  CheckCircle, 
  AlertTriangle, 
  ShieldAlert, 
  BarChart3, 
  HelpCircle,
  FileCheck2
} from 'lucide-react';
import { api } from '../../lib/api';
import { BenchmarkReport } from '../../types';

export const BenchmarkView: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<BenchmarkReport | null>(null);

  const handleRunBenchmark = async () => {
    setLoading(true);
    try {
      const data = await api.runBenchmark();
      setReport(data);
    } catch (err: any) {
      alert(`Benchmark Run Error: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Award className="w-5 h-5 text-purple-400" />
            <span>VR-Bench Adversarial Security Benchmark</span>
          </h2>
          <p className="text-xs text-gray-400 mt-1">
            Standardized evaluation testing whether AI security systems distinguish isolated CVEs from contextual attack chains.
          </p>
        </div>

        <button
          onClick={handleRunBenchmark}
          disabled={loading}
          className="px-4 py-2 bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white rounded-lg text-xs font-semibold flex items-center gap-2 shadow-lg shadow-purple-600/20"
        >
          <Play className="w-4 h-4 fill-current" />
          <span>{loading ? 'Executing 50 Test Cases...' : 'Run VR-Bench 5-Baseline Suite'}</span>
        </button>
      </div>

      {/* Benchmark Philosophy Banner */}
      <div className="bg-[#111827] border border-purple-500/20 p-5 rounded-xl text-xs space-y-2">
        <span className="font-semibold text-purple-300 flex items-center gap-1.5">
          <HelpCircle className="w-4 h-4" />
          Offensive Security AI Evaluation Methodology
        </span>
        <p className="text-gray-400 leading-relaxed">
          Standard accuracy is misleading in vulnerability prediction due to severe class imbalance. VulnReason evaluates ranking quality using 
          <strong> nDCG@10</strong> and <strong>Precision@K</strong>, while strictly measuring 
          <strong> Unsupported Claim Rates (UCR)</strong> and <strong>Prompt Injection Resistance</strong> against hidden instructions embedded in CVE text.
        </p>
      </div>

      {/* Results Table */}
      {report && (
        <div className="space-y-6">
          <div className="bg-[#111827] border border-gray-800 rounded-xl overflow-hidden shadow-xl">
            <div className="p-4 bg-gray-900/80 border-b border-gray-800 flex items-center justify-between">
              <span className="text-xs font-semibold text-white uppercase tracking-wider">
                Comparative Baseline Scorecard ({report.total_scenarios_evaluated} Scenarios)
              </span>
              <span className="text-[11px] text-gray-400 font-mono">
                Timestamp: {new Date(report.evaluation_timestamp).toLocaleTimeString()}
              </span>
            </div>

            <table className="w-full text-left text-xs">
              <thead className="bg-gray-950 text-gray-400 uppercase font-semibold border-b border-gray-800">
                <tr>
                  <th className="py-3 px-4">Prioritization Baseline</th>
                  <th className="py-3 px-4">nDCG@10</th>
                  <th className="py-3 px-4">Precision@20</th>
                  <th className="py-3 px-4">Recall@20</th>
                  <th className="py-3 px-4">Unsupported Claims (UCR)</th>
                  <th className="py-3 px-4">Injection Defense</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/60 font-mono">
                {report.baselines.map((b, idx) => {
                  const isTop = b.baseline_name.includes('FULL_SYSTEM');
                  return (
                    <tr 
                      key={idx}
                      className={isTop ? 'bg-purple-950/20 border-l-2 border-purple-500' : 'hover:bg-gray-800/30'}
                    >
                      <td className="py-3.5 px-4 font-sans font-medium text-white">
                        <div className="flex items-center gap-2">
                          <span>{b.baseline_name}</span>
                          {isTop && (
                            <span className="text-[10px] bg-purple-500/20 text-purple-400 border border-purple-500/40 px-1.5 py-0.2 rounded font-mono">
                              OURS
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="py-3.5 px-4 font-bold text-emerald-400">
                        {b.ndcg_at_k.toFixed(2)}
                      </td>
                      <td className="py-3.5 px-4 text-gray-300">
                        {(b.precision_at_k * 100).toFixed(0)}%
                      </td>
                      <td className="py-3.5 px-4 text-gray-300">
                        {(b.recall_at_k * 100).toFixed(0)}%
                      </td>
                      <td className="py-3.5 px-4">
                        <span className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                          b.unsupported_claim_rate === 0
                            ? 'bg-emerald-500/10 text-emerald-400'
                            : 'bg-red-500/10 text-red-400'
                        }`}>
                          {(b.unsupported_claim_rate * 100).toFixed(1)}%
                        </span>
                      </td>
                      <td className="py-3.5 px-4">
                        <span className="text-emerald-400 font-bold">
                          {b.prompt_injection_resistance_pct.toFixed(0)}%
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Adversarial Summary */}
          <div className="bg-gray-900/60 border border-gray-800 p-5 rounded-xl text-xs space-y-2">
            <span className="font-semibold text-gray-200 block">Adversarial Evaluation Findings:</span>
            <p className="text-gray-400 leading-relaxed">{report.adversarial_findings_summary}</p>
          </div>
        </div>
      )}
    </div>
  );
};
