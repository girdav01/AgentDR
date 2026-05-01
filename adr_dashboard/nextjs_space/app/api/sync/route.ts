export const dynamic = 'force-dynamic';
import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth-options';
import { prisma } from '@/lib/prisma';
import fs from 'fs';
import path from 'path';

export async function POST() {
  const session = await getServerSession(authOptions);
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  try {
    const jsonlPath = path.join(process.cwd(), 'data', 'events.jsonl');
    if (!fs.existsSync(jsonlPath)) {
      return NextResponse.json({ error: 'JSONL file not found', synced: 0 });
    }
    const lines = fs.readFileSync(jsonlPath, 'utf-8').split('\n').filter((l: string) => l.trim());
    let synced = 0;
    for (const line of lines) {
      try {
        const data = JSON.parse(line);
        const ts = new Date(data.timestamp);
        const existing = await prisma.event.findFirst({
          where: { timestamp: ts, eventType: data.event_type ?? 'unknown' },
        });
        if (!existing) {
          await prisma.event.create({
            data: {
              timestamp: ts,
              eventType: data.event_type ?? 'unknown',
              details: JSON.stringify(data.details ?? {}),
              riskLevel: data.risk_level ?? 'low',
              agentDetected: data.agent_detected ?? null,
              source: data.source ?? null,
              tags: data.tags ? JSON.stringify(data.tags) : null,
            },
          });
          synced++;
        }
      } catch { /* skip invalid lines */ }
    }
    return NextResponse.json({ synced, total: lines.length });
  } catch (error: any) {
    return NextResponse.json({ error: error?.message ?? 'Server error' }, { status: 500 });
  }
}
