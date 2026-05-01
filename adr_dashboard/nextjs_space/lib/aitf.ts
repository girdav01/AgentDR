// CoSAI OCSF Category 7 constants and helpers
// ─────────────────────────────────────────────
// Detection signatures, endpoints, and policies are loaded from the
// CoSAI Community JSON rule files (data/cosai-community/) so they can
// be updated without modifying source code.

import agentSignaturesData from '@/data/cosai-community/rules/agent-signatures.json';
import detectionRulesData from '@/data/cosai-community/policies/detection-rules.json';

// ── OCSF Class metadata (static — part of the OCSF spec, not community rules) ──

export const OCSF_CLASSES: Record<number, { label: string; color: string; icon: string }> = {
  7001: { label: 'Model Inference', color: 'text-blue-400', icon: '🧠' },
  7002: { label: 'Agent Activity', color: 'text-purple-400', icon: '🤖' },
  7003: { label: 'Tool Execution', color: 'text-cyan-400', icon: '🔧' },
  7004: { label: 'Data Retrieval', color: 'text-teal-400', icon: '📊' },
  7005: { label: 'Security Finding', color: 'text-red-400', icon: '🛡️' },
  7006: { label: 'Supply Chain', color: 'text-orange-400', icon: '🔗' },
  7007: { label: 'Governance', color: 'text-yellow-400', icon: '📋' },
  7008: { label: 'Identity', color: 'text-green-400', icon: '🔑' },
  7009: { label: 'Model Operations', color: 'text-indigo-400', icon: '⚙️' },
  7010: { label: 'Asset Inventory', color: 'text-pink-400', icon: '📦' },
};

export const OCSF_CLASS_COLORS: Record<number, string> = {
  7001: '#60a5fa', 7002: '#c084fc', 7003: '#22d3ee', 7004: '#2dd4bf',
  7005: '#f87171', 7006: '#fb923c', 7007: '#facc15', 7008: '#4ade80',
  7009: '#818cf8', 7010: '#f472b6',
};

// ── Detection rules — loaded from cosai-community/policies/detection-rules.json ──

export const DETECTION_RULES: Record<string, { name: string; category: string; severity: string }> =
  Object.fromEntries(
    detectionRulesData.rules.map((r) => [r.id, { name: r.name, category: r.category, severity: r.severity }])
  );

export function getClassLabel(classUid: number | null | undefined): string {
  if (!classUid) return 'Unknown';
  return OCSF_CLASSES[classUid]?.label ?? `Class ${classUid}`;
}

export function getClassIcon(classUid: number | null | undefined): string {
  if (!classUid) return '❓';
  return OCSF_CLASSES[classUid]?.icon ?? '❓';
}

export function getClassColor(classUid: number | null | undefined): string {
  if (!classUid) return 'text-muted-foreground';
  return OCSF_CLASSES[classUid]?.color ?? 'text-muted-foreground';
}

// ── Agent categories — loaded from cosai-community/rules/agent-signatures.json ──

export const AGENT_CATEGORIES: Record<string, { label: string; icon: string; color: string; description: string }> =
  Object.fromEntries(
    Object.entries(agentSignaturesData.categories).map(([key, cat]) => [
      key,
      { label: cat.label, icon: cat.icon, color: cat.color, description: cat.description },
    ])
  );

// ── Known agent signatures — loaded from cosai-community/rules/agent-signatures.json ──

export const KNOWN_AGENTS: Record<string, { name: string; category: string; risk: string }> =
  Object.fromEntries(
    agentSignaturesData.signatures.map((s) => [s.id, { name: s.name, category: s.category, risk: s.risk }])
  );

export function getAgentCategory(agentName: string | null | undefined): string {
  if (!agentName) return 'unknown';
  const key = agentName.toLowerCase().replace(/[^a-z0-9-]/g, '');
  return KNOWN_AGENTS[key]?.category ?? 'unknown';
}
