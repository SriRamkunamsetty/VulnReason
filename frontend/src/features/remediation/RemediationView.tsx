import React, { useState, useEffect } from 'react';
import { 
  CheckCircle2, 
  Clock, 
  ShieldCheck, 
  AlertCircle, 
  Upload, 
  FileCheck,
  Check,
  X
} from 'lucide-react';
import { api } from '../../lib/api';
import { RemediationTask } from '../../types';

export const RemediationView: React.FC = () => {
  const [tasks, setTasks] = useState<RemediationTask[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedTask, setSelectedTask] = useState<RemediationTask | null>(null);
  const [verifyType, setVerifyType] = useState('SCANNER_RESCAN');
  const [proofJson, setProofJson] = useState('{\n  "scan_id": "QUALYS-RESCAN-9812",\n  "status": "VULNERABILITY_NOT_DETECTED",\n  "hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"\n}');
  const [saving, setSaving] = useState(false);

  const loadTasks = async () => {
    setLoading(true);
    try {
      const data = await api.getRemediationTasks();
      setTasks(data);
    } catch {
      // fallback
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadTasks();
  }, []);

  const handleResolveTask = async () => {
    if (!selectedTask) return;
    setSaving(true);
    try {
      let parsedProof = {};
      try {
        parsedProof = JSON.parse(proofJson);
      } catch {
        alert("Verification evidence must be valid JSON.");
        setSaving(false);
        return;
      }

      await api.updateTaskStatus(selectedTask.id, 'RESOLVED', verifyType, parsedProof);
      setSelectedTask(null);
      await loadTasks();
    } catch (err: any) {
      alert(`Verification Gate Rejection: ${err.message}`);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      <div>
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <CheckCircle2 className="w-5 h-5 text-emerald-400" />
          <span>Remediation Workflow & Verification Gates</span>
        </h2>
        <p className="text-xs text-gray-400 mt-1">
          Findings cannot be closed on AI suggestion alone. Closure requires cryptographically signed verification or rescan evidence.
        </p>
      </div>

      <div className="bg-[#111827] border border-gray-800 rounded-xl overflow-hidden shadow-xl">
        <table className="w-full text-left text-xs">
          <thead className="bg-gray-900/80 text-gray-400 uppercase font-semibold border-b border-gray-800">
            <tr>
              <th className="py-3 px-4">Task ID / CVE</th>
              <th className="py-3 px-4">Assigned Team</th>
              <th className="py-3 px-4">SLA Deadline</th>
              <th className="py-3 px-4">Current Status</th>
              <th className="py-3 px-4">Verification Evidence</th>
              <th className="py-3 px-4 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/60 font-mono">
            {tasks.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-8 text-center text-gray-500 font-sans">
                  No active remediation tasks. Assign tasks from the Findings triage tab.
                </td>
              </tr>
            ) : (
              tasks.map((t) => (
                <tr key={t.id} className="hover:bg-gray-800/30">
                  <td className="py-3.5 px-4 font-sans font-medium text-white">
                    <span className="font-mono text-xs">{t.cve_id}</span>
                  </td>
                  <td className="py-3.5 px-4 text-gray-300 font-sans">{t.assigned_team}</td>
                  <td className="py-3.5 px-4 text-gray-300">
                    {new Date(t.due_date).toLocaleDateString()}
                  </td>
                  <td className="py-3.5 px-4">
                    <span className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                      t.status === 'RESOLVED' 
                        ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                        : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                    }`}>
                      {t.status}
                    </span>
                  </td>
                  <td className="py-3.5 px-4 font-sans text-gray-400">
                    {t.evidence_count > 0 ? (
                      <span className="text-emerald-400 flex items-center gap-1 font-mono">
                        <Check className="w-3.5 h-3.5" />
                        {t.evidence_count} Proof Attached
                      </span>
                    ) : (
                      <span className="text-gray-500 italic">No proof attached</span>
                    )}
                  </td>
                  <td className="py-3.5 px-4 text-right font-sans">
                    {t.status !== 'RESOLVED' ? (
                      <button
                        onClick={() => setSelectedTask(t)}
                        className="px-3 py-1 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-xs font-semibold"
                      >
                        Submit Verification & Close
                      </button>
                    ) : (
                      <span className="text-xs text-gray-500">Verified Closed</span>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Verification Gate Modal */}
      {selectedTask && (
        <div className="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-4">
          <div className="bg-[#111827] border border-gray-800 max-w-lg w-full p-6 rounded-xl space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-gray-800 pb-3">
              <h3 className="font-bold text-white text-base flex items-center gap-2">
                <FileCheck className="w-5 h-5 text-emerald-400" />
                <span>Verification Gate: {selectedTask.cve_id}</span>
              </h3>
              <button 
                onClick={() => setSelectedTask(null)}
                className="text-gray-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-2 text-xs">
              <label className="text-gray-300 font-semibold block">Verification Evidence Type:</label>
              <select
                value={verifyType}
                onChange={(e) => setVerifyType(e.target.value)}
                className="w-full bg-gray-900 border border-gray-800 rounded p-2 text-white"
              >
                <option value="SCANNER_RESCAN">Authenticated Scanner Rescan (Qualys / Tenable)</option>
                <option value="CONFIGURATION_PROOF">Configuration Diff & Firewall Rule Proof</option>
                <option value="PATCH_COMMIT">Git Commit Hash & Package Lockfile</option>
              </select>
            </div>

            <div className="space-y-2 text-xs">
              <label className="text-gray-300 font-semibold block">Cryptographic Proof Payload (JSON):</label>
              <textarea
                rows={6}
                value={proofJson}
                onChange={(e) => setProofJson(e.target.value)}
                className="w-full bg-gray-950 font-mono border border-gray-800 rounded p-3 text-xs text-emerald-400 focus:outline-none focus:border-emerald-500"
              />
            </div>

            <div className="pt-2 flex justify-end gap-3">
              <button
                onClick={() => setSelectedTask(null)}
                className="px-3 py-1.5 text-xs text-gray-400 hover:text-white"
              >
                Cancel
              </button>
              <button
                onClick={handleResolveTask}
                disabled={saving}
                className="px-4 py-1.5 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white rounded text-xs font-semibold shadow-lg shadow-emerald-600/20"
              >
                {saving ? 'Verifying Proof...' : 'Verify Evidence & Close Finding'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
