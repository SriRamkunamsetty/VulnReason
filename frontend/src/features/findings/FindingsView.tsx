import React, { useState } from 'react';
import { 
  Search, 
  Filter, 
  AlertCircle, 
  CheckCircle, 
  Flame, 
  Sparkles, 
  ShieldCheck, 
  X,
  ExternalLink,
  Clock,
  Layers
} from 'lucide-react';
import { Finding, AIAssessment } from '../../types';
import { api } from '../../lib/api';

interface FindingsViewProps {
  findings: Finding[];
  onRefresh: () => void;
}

export const FindingsView: React.FC<FindingsViewProps> = ({ findings, onRefresh }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [priorityFilter, setPriorityFilter] = useState('ALL');
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [aiAssessment, setAiAssessment] = useState<AIAssessment | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [overrideModal, setOverrideModal] = useState(false);
  const [newApplicability, setNewApplicability] = useState('NOT_APPLICABLE');
  const [overrideRationale, setOverrideRationale] = useState('');
  const [overrideSaving, setOverrideSaving] = useState(false);

  // Filter logic
  const filtered = findings.filter(f => {
    const matchesSearch = 
      f.cve_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (f.package_name && f.package_name.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (f.asset_hostname && f.asset_hostname.toLowerCase().includes(searchTerm.toLowerCase()));

    const matchesPriority = priorityFilter === 'ALL' || f.contextual_priority === priorityFilter;
    return matchesSearch && matchesPriority;
  });

  const handleSelectFinding = async (finding: Finding) => {
    setSelectedFinding(finding);
    setAiAssessment(null);
    try {
      const detail = await api.getFindingDetail(finding.id);
      setSelectedFinding(detail);
    } catch {
      // fallback to row finding
    }
  };

  const handleTriggerAI = async () => {
    if (!selectedFinding) return;
    setAiLoading(true);
    try {
      const assessment = await api.triggerAIReasoning(selectedFinding.id);
      setAiAssessment(assessment);
    } catch (err: any) {
      alert(`AI Assessment Error: ${err.message}`);
    } finally {
      setAiLoading(false);
    }
  };

  const handleSaveOverride = async () => {
    if (!selectedFinding || !overrideRationale) return;
    setOverrideSaving(true);
    try {
      const updated = await api.overrideApplicability(selectedFinding.id, newApplicability, overrideRationale);
      setSelectedFinding(updated);
      setOverrideModal(false);
      setOverrideRationale('');
      onRefresh();
    } catch (err: any) {
      alert(`Override Error: ${err.message}`);
    } finally {
      setOverrideSaving(false);
    }
  };

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      {/* Header and Controls */}
      <div className="flex flex-col md:flex-row gap-4 items-start md:items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white">Contextual Finding Triage</h2>
          <p className="text-xs text-gray-400">
            Ranked by environmental reachability, KEV exploitation signals, and version applicability.
          </p>
        </div>

        <div className="flex gap-3 w-full md:w-auto">
          {/* Search Box */}
          <div className="relative flex-1 md:w-72">
            <Search className="w-4 h-4 text-gray-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search CVE, package, host..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-[#111827] border border-gray-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          {/* Priority Filter */}
          <select
            value={priorityFilter}
            onChange={(e) => setPriorityFilter(e.target.value)}
            className="bg-[#111827] border border-gray-800 rounded-lg px-3 py-1.5 text-xs text-gray-300 focus:outline-none focus:border-blue-500"
          >
            <option value="ALL">All Priorities</option>
            <option value="P0_URGENT">P0 — Urgent</option>
            <option value="P1_HIGH">P1 — High</option>
            <option value="P2_MEDIUM">P2 — Medium</option>
            <option value="P3_LOW">P3 — Low</option>
          </select>
        </div>
      </div>

      {/* Main Findings Table */}
      <div className="bg-[#111827] border border-gray-800 rounded-xl overflow-hidden shadow-xl">
        <table className="w-full text-left text-xs">
          <thead className="bg-gray-900/80 text-gray-400 uppercase tracking-wider font-semibold border-b border-gray-800">
            <tr>
              <th className="py-3.5 px-4">Vulnerability / CVE</th>
              <th className="py-3.5 px-4">Component & Version</th>
              <th className="py-3.5 px-4">Asset & Exposure</th>
              <th className="py-3.5 px-4">Applicability</th>
              <th className="py-3.5 px-4">Contextual Priority</th>
              <th className="py-3.5 px-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/60 font-mono">
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-8 text-center text-gray-500 font-sans">
                  No findings match current search or filters.
                </td>
              </tr>
            ) : (
              filtered.map((f) => {
                const isP0 = f.contextual_priority === 'P0_URGENT';
                const isP1 = f.contextual_priority === 'P1_HIGH';
                return (
                  <tr 
                    key={f.id}
                    onClick={() => handleSelectFinding(f)}
                    className="hover:bg-gray-800/40 cursor-pointer transition-colors"
                  >
                    {/* CVE */}
                    <td className="py-3 px-4 font-sans">
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-bold text-white text-xs">{f.cve_id}</span>
                        {f.cisa_kev_listed && (
                          <span className="flex items-center gap-1 bg-purple-500/10 text-purple-400 border border-purple-500/30 text-[10px] px-1.5 py-0.5 rounded font-mono font-bold">
                            <Flame className="w-2.5 h-2.5" />
                            KEV
                          </span>
                        )}
                      </div>
                      <div className="text-[11px] text-gray-400 font-mono mt-0.5">
                        EPSS: {(f.epss_score ? (f.epss_score * 100).toFixed(1) + '%' : 'N/A')}
                      </div>
                    </td>

                    {/* Component */}
                    <td className="py-3 px-4">
                      <div className="text-gray-200">{f.package_name || 'System Package'}</div>
                      <div className="text-[11px] text-gray-500 font-mono">
                        inst: {f.installed_version || 'unknown'} &rarr; fix: {f.fixed_version || 'unreleased'}
                      </div>
                    </td>

                    {/* Asset */}
                    <td className="py-3 px-4 font-sans">
                      <div className="text-gray-200 text-xs font-mono">{f.asset_hostname || 'prod-host'}</div>
                      <span className={`text-[10px] font-mono uppercase px-1.5 py-0.5 rounded ${
                        f.asset_exposure === 'INTERNET_FACING' 
                          ? 'bg-red-500/10 text-red-400 border border-red-500/30' 
                          : 'bg-gray-800 text-gray-400'
                      }`}>
                        {f.asset_exposure || 'INTERNAL'}
                      </span>
                    </td>

                    {/* Applicability */}
                    <td className="py-3 px-4 font-sans">
                      <span className={`text-[11px] px-2 py-0.5 rounded-full font-medium ${
                        f.applicability === 'CONFIRMED_APPLICABLE'
                          ? 'bg-red-500/10 text-red-400 border border-red-500/20'
                          : f.applicability === 'NOT_APPLICABLE'
                          ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                          : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                      }`}>
                        {f.applicability.replace('_', ' ')}
                      </span>
                    </td>

                    {/* Contextual Priority */}
                    <td className="py-3 px-4 font-sans">
                      <span className={`text-xs font-bold px-2 py-1 rounded font-mono ${
                        isP0
                          ? 'bg-red-500/20 text-red-400 border border-red-500/40'
                          : isP1
                          ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                          : 'bg-blue-500/20 text-blue-400 border border-blue-500/40'
                      }`}>
                        {f.contextual_priority}
                      </span>
                    </td>

                    {/* Action */}
                    <td className="py-3 px-4 text-right font-sans">
                      <button 
                        onClick={(e) => {
                          e.stopPropagation();
                          handleSelectFinding(f);
                        }}
                        className="text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 px-2.5 py-1 rounded transition-colors"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Detail Drawer Modal */}
      {selectedFinding && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex justify-end">
          <div className="w-full max-w-2xl bg-[#0E131F] border-l border-gray-800 h-full overflow-y-auto p-6 space-y-6 shadow-2xl">
            {/* Drawer Header */}
            <div className="flex items-start justify-between border-b border-gray-800 pb-4">
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-lg font-bold text-white font-mono">{selectedFinding.cve_id}</h3>
                  <span className="text-xs font-mono font-bold bg-red-500/20 text-red-400 px-2 py-0.5 rounded border border-red-500/30">
                    {selectedFinding.contextual_priority}
                  </span>
                </div>
                <p className="text-xs text-gray-400 mt-1">Host: {selectedFinding.asset_hostname || 'internal-app'}</p>
              </div>
              <button 
                onClick={() => setSelectedFinding(null)}
                className="text-gray-400 hover:text-white p-1 rounded-lg hover:bg-gray-800"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Environmental Signals Grid */}
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="bg-gray-900/60 p-3 rounded-lg border border-gray-800">
                <span className="text-gray-400 block mb-1">CISA KEV Status:</span>
                <span className={`font-mono font-bold ${selectedFinding.cisa_kev_listed ? 'text-purple-400' : 'text-gray-300'}`}>
                  {selectedFinding.cisa_kev_listed ? 'CONFIRMED LISTED' : 'Not Listed'}
                </span>
              </div>
              <div className="bg-gray-900/60 p-3 rounded-lg border border-gray-800">
                <span className="text-gray-400 block mb-1">FIRST EPSS Score:</span>
                <span className="font-mono font-bold text-blue-400">
                  {selectedFinding.epss_score ? (selectedFinding.epss_score * 100).toFixed(2) + '%' : 'N/A'}
                </span>
              </div>
              <div className="bg-gray-900/60 p-3 rounded-lg border border-gray-800">
                <span className="text-gray-400 block mb-1">Asset Exposure Tier:</span>
                <span className="font-mono font-bold text-amber-400">
                  {selectedFinding.asset_exposure || 'INTERNAL'}
                </span>
              </div>
              <div className="bg-gray-900/60 p-3 rounded-lg border border-gray-800">
                <span className="text-gray-400 block mb-1">Applicability:</span>
                <span className="font-mono font-bold text-emerald-400">
                  {selectedFinding.applicability}
                </span>
              </div>
            </div>

            {/* Applicability Rationale & Override Button */}
            <div className="bg-gray-900/40 border border-gray-800 p-4 rounded-xl space-y-2 text-xs">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-gray-300">Applicability Evidence:</span>
                <button
                  onClick={() => setOverrideModal(true)}
                  className="text-blue-400 hover:underline"
                >
                  Override Decision
                </button>
              </div>
              <p className="text-gray-400">
                {selectedFinding.applicability_rationale || 'Evaluated against SemVer range matching.'}
              </p>
            </div>

            {/* AI Reasoning Section */}
            <div className="border-t border-gray-800 pt-5 space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Sparkles className="w-4 h-4 text-blue-400" />
                  <h4 className="text-sm font-semibold text-white">AI Structured Reasoning & Citation Audit</h4>
                </div>
                <button
                  onClick={handleTriggerAI}
                  disabled={aiLoading}
                  className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5"
                >
                  {aiLoading ? 'Generating & Auditing...' : 'Run Reasoning Audit'}
                </button>
              </div>

              {aiAssessment && (
                <div className="space-y-4 bg-gray-950 p-4 rounded-xl border border-gray-800 text-xs">
                  {/* Audit Pass Pill */}
                  <div className="flex items-center justify-between pb-2 border-b border-gray-800">
                    <span className="text-gray-400">Deterministic Citation Audit:</span>
                    <span className={`px-2 py-0.5 rounded font-mono font-bold text-[11px] ${
                      aiAssessment.citation_audit_passed
                        ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                        : 'bg-red-500/20 text-red-400 border border-red-500/30'
                    }`}>
                      {aiAssessment.citation_audit_passed ? '0.0% Unsupported Claims (AUDIT PASSED)' : 'AUDIT FAILED'}
                    </span>
                  </div>

                  {/* Summary */}
                  <div>
                    <span className="font-semibold text-gray-300 block mb-1">Narrative:</span>
                    <p className="text-gray-300 leading-relaxed">{aiAssessment.narrative_summary}</p>
                  </div>

                  {/* Claims List */}
                  <div className="space-y-2">
                    <span className="font-semibold text-gray-300 block">Structured Claims:</span>
                    {aiAssessment.claims_payload.map((c, i) => (
                      <div key={i} className="bg-gray-900/80 p-2.5 rounded border border-gray-800 space-y-1">
                        <div className="flex items-center justify-between text-[11px]">
                          <span className="font-mono text-blue-400">{c.claim_id} [{c.claim_type}]</span>
                          <span className="text-gray-500 font-mono">evidence: {c.supporting_evidence_ids.join(', ')}</span>
                        </div>
                        <p className="text-gray-300">{c.statement}</p>
                      </div>
                    ))}
                  </div>

                  {/* Remediation Leverage */}
                  {aiAssessment.remediation_recommendations.length > 0 && (
                    <div className="pt-2 border-t border-gray-800">
                      <span className="font-semibold text-emerald-400 block mb-1">Recommended Fix & Leverage:</span>
                      <p className="text-gray-300">{aiAssessment.remediation_recommendations[0].action}</p>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Override Modal */}
      {overrideModal && (
        <div className="fixed inset-0 bg-black/80 z-60 flex items-center justify-center p-4">
          <div className="bg-[#111827] border border-gray-800 max-w-md w-full p-6 rounded-xl space-y-4 shadow-2xl">
            <h3 className="text-base font-bold text-white">Override Vulnerability Applicability</h3>
            <div className="space-y-2 text-xs">
              <label className="text-gray-400">Target Applicability:</label>
              <select
                value={newApplicability}
                onChange={(e) => setNewApplicability(e.target.value)}
                className="w-full bg-gray-900 border border-gray-800 rounded p-2 text-white"
              >
                <option value="NOT_APPLICABLE">NOT_APPLICABLE (Verified Not Affected)</option>
                <option value="CONFIRMED_APPLICABLE">CONFIRMED_APPLICABLE</option>
                <option value="LIKELY_APPLICABLE">LIKELY_APPLICABLE</option>
              </select>
            </div>

            <div className="space-y-2 text-xs">
              <label className="text-gray-400">Auditable Rationale (Mandatory):</label>
              <textarea
                rows={3}
                placeholder="e.g. Verified with engineering team that vulnerable module is disabled in compiler flags."
                value={overrideRationale}
                onChange={(e) => setOverrideRationale(e.target.value)}
                className="w-full bg-gray-900 border border-gray-800 rounded p-2 text-white placeholder-gray-500"
              />
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button 
                onClick={() => setOverrideModal(false)}
                className="px-3 py-1.5 rounded text-xs text-gray-400 hover:text-white"
              >
                Cancel
              </button>
              <button 
                onClick={handleSaveOverride}
                disabled={overrideSaving || !overrideRationale}
                className="px-4 py-1.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded text-xs font-semibold"
              >
                {overrideSaving ? 'Applying...' : 'Apply Override'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
