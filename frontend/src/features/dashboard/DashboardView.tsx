import React from 'react';
import { 
  AlertTriangle, 
  GitPullRequest, 
  Flame, 
  CheckCircle, 
  ArrowUpRight, 
  ShieldCheck,
  Server,
  Terminal,
  Sliders
} from 'lucide-react';
import { Finding, AttackPath } from '../../types';

interface DashboardViewProps {
  findings: Finding[];
  attackPaths: AttackPath[];
  onNavigate: (tab: any) => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({ 
  findings, 
  attackPaths, 
  onNavigate 
}) => {
  const p0Findings = findings.filter(f => f.contextual_priority === 'P0_URGENT');
  const p1Findings = findings.filter(f => f.contextual_priority === 'P1_HIGH');
  const p2Findings = findings.filter(f => f.contextual_priority === 'P2_MEDIUM');
  const p3Findings = findings.filter(f => f.contextual_priority === 'P3_LOW');
  const kevFindings = findings.filter(f => f.cisa_kev_listed);
  const criticalPaths = attackPaths.filter(p => p.target_criticality === 'MISSION_CRITICAL');

  return (
    <div className="p-8 space-y-8 max-w-7xl mx-auto">
      {/* Welcome Banner */}
      <div className="flex items-center justify-between bg-gradient-to-r from-blue-900/30 via-gray-900 to-gray-900 border border-blue-500/20 p-6 rounded-xl">
        <div className="space-y-1">
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <span>Enterprise Vulnerability Intelligence & Attack Paths</span>
            <span className="text-xs bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 px-2 py-0.5 rounded-full font-mono">
              Live Topology Active
            </span>
          </h2>
          <p className="text-sm text-gray-400 max-w-2xl">
            Deterministic risk decisions combining CISA KEV, FIRST EPSS, verified asset exposure boundaries, and lateral movement paths.
          </p>
        </div>
        <div className="flex gap-3">
          <button 
            onClick={() => onNavigate('simulator')}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm font-semibold transition-all flex items-center gap-2 shadow-lg shadow-blue-600/20"
          >
            <span>Simulate Mitigation</span>
            <ArrowUpRight className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-5">
        {/* Card 1: P0 Urgent */}
        <div className="bg-[#111827] border border-red-500/30 p-5 rounded-xl space-y-3 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Urgent Action (P0)</span>
            <div className="w-8 h-8 rounded-lg bg-red-500/20 flex items-center justify-center">
              <AlertTriangle className="w-4 h-4 text-red-400" />
            </div>
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-bold font-mono text-red-400">{p0Findings.length}</span>
            <span className="text-xs text-gray-400">findings (24-48h SLA)</span>
          </div>
          <div className="text-xs text-gray-400 flex items-center gap-1.5 pt-1 border-t border-gray-800">
            <span className="text-red-400 font-semibold">{kevFindings.length} in CISA KEV</span> on active perimeter
          </div>
        </div>

        {/* Card 2: Attack Paths */}
        <div className="bg-[#111827] border border-amber-500/30 p-5 rounded-xl space-y-3 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Reachable Attack Paths</span>
            <div className="w-8 h-8 rounded-lg bg-amber-500/20 flex items-center justify-center">
              <GitPullRequest className="w-4 h-4 text-amber-400" />
            </div>
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-bold font-mono text-amber-400">{criticalPaths.length}</span>
            <span className="text-xs text-gray-400">paths to Crown Jewels</span>
          </div>
          <div className="text-xs text-gray-400 flex items-center gap-1.5 pt-1 border-t border-gray-800">
            <span className="text-amber-400 font-semibold">100% verified edges</span> (No unverified jumps)
          </div>
        </div>

        {/* Card 3: CISA KEV */}
        <div className="bg-[#111827] border border-purple-500/30 p-5 rounded-xl space-y-3 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider">In-the-Wild Exploits</span>
            <div className="w-8 h-8 rounded-lg bg-purple-500/20 flex items-center justify-center">
              <Flame className="w-4 h-4 text-purple-400" />
            </div>
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-bold font-mono text-purple-400">{kevFindings.length}</span>
            <span className="text-xs text-gray-400">active CVEs cataloged</span>
          </div>
          <div className="text-xs text-gray-400 flex items-center gap-1.5 pt-1 border-t border-gray-800">
            <span className="text-purple-400 font-semibold">EPSS &gt;90th %ile</span> validated
          </div>
        </div>

        {/* Card 4: Verification Proofs */}
        <div className="bg-[#111827] border border-emerald-500/30 p-5 rounded-xl space-y-3 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Remediation Gate</span>
            <div className="w-8 h-8 rounded-lg bg-emerald-500/20 flex items-center justify-center">
              <CheckCircle className="w-4 h-4 text-emerald-400" />
            </div>
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-bold font-mono text-emerald-400">100%</span>
            <span className="text-xs text-gray-400">evidence required</span>
          </div>
          <div className="text-xs text-gray-400 flex items-center gap-1.5 pt-1 border-t border-gray-800">
            <span className="text-emerald-400 font-semibold">Zero self-closure</span> without proof
          </div>
        </div>
      </div>

      {/* Middle Section: Prioritization Breakdown & Architecture Philosophy */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Priority Tier Distribution */}
        <div className="bg-[#111827] border border-gray-800 p-6 rounded-xl space-y-4 lg:col-span-1">
          <h3 className="font-semibold text-white flex items-center justify-between">
            <span>Contextual Priority Breakdown</span>
            <span className="text-xs text-gray-400 font-mono">{findings.length} Total</span>
          </h3>

          <div className="space-y-3 pt-2">
            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-red-400 font-semibold">P0 — Urgent Review (SLA 48h)</span>
                <span className="font-mono text-gray-300">{p0Findings.length}</span>
              </div>
              <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
                <div className="h-full bg-red-500" style={{ width: `${(p0Findings.length / (findings.length || 1)) * 100}%` }}></div>
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-amber-400 font-semibold">P1 — High Priority (SLA 7d)</span>
                <span className="font-mono text-gray-300">{p1Findings.length}</span>
              </div>
              <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
                <div className="h-full bg-amber-500" style={{ width: `${(p1Findings.length / (findings.length || 1)) * 100}%` }}></div>
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-blue-400 font-semibold">P2 — Medium Priority (SLA 30d)</span>
                <span className="font-mono text-gray-300">{p2Findings.length}</span>
              </div>
              <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
                <div className="h-full bg-blue-500" style={{ width: `${(p2Findings.length / (findings.length || 1)) * 100}%` }}></div>
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-gray-400 font-semibold">P3 — Low / Standard (SLA 90d)</span>
                <span className="font-mono text-gray-300">{p3Findings.length}</span>
              </div>
              <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
                <div className="h-full bg-gray-600" style={{ width: `${(p3Findings.length / (findings.length || 1)) * 100}%` }}></div>
              </div>
            </div>
          </div>

          <div className="pt-3 border-t border-gray-800 text-xs text-gray-400">
            <p>Non-multiplicative multi-signal matrix. Never multiplies ordinal CVSS with EPSS probabilities.</p>
          </div>
        </div>

        {/* Why VulnReason is Different */}
        <div className="bg-[#111827] border border-gray-800 p-6 rounded-xl space-y-4 lg:col-span-2">
          <h3 className="font-semibold text-white flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-blue-400" />
            <span>Offensive Security & AI Reasoning Innovations</span>
          </h3>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div className="bg-gray-900/60 p-4 rounded-lg border border-gray-800 space-y-1.5">
              <span className="font-semibold text-blue-400 flex items-center gap-1.5">
                <GitPullRequest className="w-3.5 h-3.5" />
                1. Evidence-Backed Attack Paths
              </span>
              <p className="text-gray-400">
                NetworkX directed graph with bounded traversal. Flags missing network or permission routes as unverified rather than hallucinating paths.
              </p>
            </div>

            <div className="bg-gray-900/60 p-4 rounded-lg border border-gray-800 space-y-1.5">
              <span className="font-semibold text-purple-400 flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5" />
                2. AI Citation & Claim Auditor
              </span>
              <p className="text-gray-400">
                Deterministic validator checks every claim in LLM outputs against database evidence IDs. Rejects unsupported claims with 0.0% tolerance.
              </p>
            </div>

            <div className="bg-gray-900/60 p-4 rounded-lg border border-gray-800 space-y-1.5">
              <span className="font-semibold text-emerald-400 flex items-center gap-1.5">
                <Sliders className="w-3.5 h-3.5" />
                3. Counterfactual Simulator
              </span>
              <p className="text-gray-400">
                Allows analysts to ask "What happens to risk if we sever port 443 or patch Log4j?" Computes broken paths in-memory without touching production.
              </p>
            </div>

            <div className="bg-gray-900/60 p-4 rounded-lg border border-gray-800 space-y-1.5">
              <span className="font-semibold text-amber-400 flex items-center gap-1.5">
                <Server className="w-3.5 h-3.5" />
                4. VR-Bench Adversarial Benchmark
              </span>
              <p className="text-gray-400">
                Evaluates prioritization across 5 baselines (CVSS-only, EPSS-only, Policy, Deterministic, Full AI) measuring nDCG@10 and injection defense.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
