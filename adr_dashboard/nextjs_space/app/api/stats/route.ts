export const dynamic = 'force-dynamic';
import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth-options';
import { prisma } from '@/lib/prisma';

export async function GET() {
  const session = await getServerSession(authOptions);
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  try {
    const [totalEvents, highRiskEvents, criticalEvents, uniqueAgents, eventsByType, eventsByRisk, eventsBySource, eventsByClass, eventsByProvider, eventsByModel, recentTimeline, topAgents, alertCount, unresolvedAlerts, alertsByRule] = await Promise.all([
      prisma.event.count(),
      prisma.event.count({ where: { riskLevel: 'high' } }),
      prisma.event.count({ where: { riskLevel: 'critical' } }),
      prisma.event.findMany({ where: { agentDetected: { not: null } }, select: { agentDetected: true }, distinct: ['agentDetected'] }),
      prisma.event.groupBy({ by: ['eventType'], _count: true, orderBy: { _count: { eventType: 'desc' } } }),
      prisma.event.groupBy({ by: ['riskLevel'], _count: true }),
      prisma.event.groupBy({ by: ['source'], _count: true }),
      prisma.event.groupBy({ by: ['classUid'], where: { classUid: { not: null } }, _count: true, orderBy: { _count: { classUid: 'desc' } } }),
      prisma.event.groupBy({ by: ['provider'], where: { provider: { not: null } }, _count: true, orderBy: { _count: { provider: 'desc' } } }),
      prisma.event.groupBy({ by: ['model'], where: { model: { not: null } }, _count: true, orderBy: { _count: { model: 'desc' } }, take: 10 }),
      prisma.event.findMany({ orderBy: { timestamp: 'asc' }, select: { timestamp: true, riskLevel: true, eventType: true, classUid: true } }),
      prisma.event.groupBy({ by: ['agentDetected'], where: { agentDetected: { not: null } }, _count: true, orderBy: { _count: { agentDetected: 'desc' } }, take: 10 }),
      prisma.alert.count(),
      prisma.alert.count({ where: { resolved: false } }),
      prisma.alert.groupBy({ by: ['ruleId'], where: { ruleId: { not: null } }, _count: true, orderBy: { _count: { ruleId: 'desc' } } }),
    ]);

    // Group timeline by hour
    const timelineMap: Record<string, { total: number; high: number; critical: number; medium: number; low: number }> = {};
    for (const e of recentTimeline) {
      const hour = new Date(e?.timestamp).toISOString().slice(0, 13) + ':00:00Z';
      if (!timelineMap[hour]) timelineMap[hour] = { total: 0, high: 0, critical: 0, medium: 0, low: 0 };
      timelineMap[hour].total += 1;
      const rl = e?.riskLevel as string;
      if (rl === 'high') timelineMap[hour].high += 1;
      else if (rl === 'critical') timelineMap[hour].critical += 1;
      else if (rl === 'medium') timelineMap[hour].medium += 1;
      else timelineMap[hour].low += 1;
    }
    const timeline = Object.entries(timelineMap).map(([hour, data]) => ({ hour, ...data })).sort((a: any, b: any) => a.hour.localeCompare(b.hour));

    // Heatmap: event types by hour of day
    const heatmapData: Record<string, Record<number, number>> = {};
    for (const e of recentTimeline) {
      const type = e?.eventType ?? 'unknown';
      const hourOfDay = new Date(e?.timestamp).getUTCHours();
      if (!heatmapData[type]) heatmapData[type] = {};
      heatmapData[type][hourOfDay] = (heatmapData[type][hourOfDay] ?? 0) + 1;
    }

    // OCSF class labels
    const CLASS_LABELS: Record<number, string> = {
      7001: 'Model Inference', 7002: 'Agent Activity', 7003: 'Tool Execution',
      7004: 'Data Retrieval', 7005: 'Security Finding', 7006: 'Supply Chain',
      7007: 'Governance', 7008: 'Identity', 7009: 'Model Operations', 7010: 'Asset Inventory',
    };

    return NextResponse.json({
      totalEvents,
      highRiskEvents,
      criticalEvents,
      uniqueAgentsCount: uniqueAgents?.length ?? 0,
      uniqueAgents: (uniqueAgents ?? []).map((a: any) => a?.agentDetected).filter(Boolean),
      eventsByType: (eventsByType ?? []).map((e: any) => ({ type: e?.eventType, count: e?._count ?? 0 })),
      eventsByRisk: (eventsByRisk ?? []).map((e: any) => ({ level: e?.riskLevel, count: e?._count ?? 0 })),
      eventsBySource: (eventsBySource ?? []).map((e: any) => ({ source: e?.source, count: e?._count ?? 0 })),
      // CoSAI OCSF-specific stats
      eventsByClass: (eventsByClass ?? []).map((e: any) => ({ classUid: e?.classUid, label: CLASS_LABELS[e?.classUid] ?? `Class ${e?.classUid}`, count: e?._count ?? 0 })),
      eventsByProvider: (eventsByProvider ?? []).map((e: any) => ({ provider: e?.provider, count: e?._count ?? 0 })),
      eventsByModel: (eventsByModel ?? []).map((e: any) => ({ model: e?.model, count: e?._count ?? 0 })),
      alertsByRule: (alertsByRule ?? []).map((a: any) => ({ ruleId: a?.ruleId, count: a?._count ?? 0 })),
      timeline,
      topAgents: (topAgents ?? []).map((a: any) => ({ agent: a?.agentDetected, count: a?._count ?? 0 })),
      alertCount,
      unresolvedAlerts,
      heatmapData,
    });
  } catch (error: any) {
    return NextResponse.json({ error: error?.message ?? 'Server error' }, { status: 500 });
  }
}
