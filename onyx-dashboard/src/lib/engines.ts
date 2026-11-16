/**
 * Typed client for the ONYX scoring-engine API (/api/v1/engines/*).
 * Every figure shown by the Intelligence page comes from these calls; nothing is recomputed in the browser.
 */

const BASE = `${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/api/v1/engines`;

export type DecayState = 'valid' | 'degrading' | 'stale' | 'obsolete';
export type CompareLevel = 'technique' | 'parent';

export interface EnginesMeta {
  ioc_types: string[];
  host_types: string[];
  tlds: string[];
  registrar_tiers: number[];
  sources: Record<string, number>;
  default_weights: Record<WeightKey, number>;
  convergence_threshold: number;
}

export type WeightKey = 'source' | 'corroboration' | 'freshness' | 'context' | 'analyst';

export interface AssessRequest {
  ioc_type: string;
  hours_since_seen: number;
  source: string;
  corroboration_count: number;
  host_type?: string;
  tld?: string;
  exploit_available?: boolean;
  contested?: boolean;
  contestation_certainty?: number;
  analyst_override_score?: number;
  weights?: Record<WeightKey, number>;
}

export interface Component {
  name: WeightKey;
  weight: number;
  value: number;
  contribution: number;
}

export interface AssessResponse {
  decay: number;
  state: DecayState;
  composite: number;
  contestation_penalty: number;
  source_known: boolean;
  analyst_component_derived: boolean;
  components: Component[];
}

export interface CurvePoint { hours: number; decay: number; state: DecayState }
export interface CurveResponse { points: CurvePoint[]; first_hour_at_or_below_half: number | null }

export interface MatrixResponse {
  level: CompareLevel;
  threshold: number;
  actors: { name: string; count: number; status: string; target: string }[];
  matrix: number[][];
  max_offdiagonal: number;
  pairs_at_or_above_threshold: number;
  top_pairs: { jaccard: number; a: string; b: string }[];
}

export interface PairResponse {
  a: string; b: string; level: CompareLevel; jaccard: number;
  shared: string[]; only_a: string[]; only_b: string[];
  convergent: boolean; threshold: number; interpretation: string;
}

export class EngineError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = 'EngineError';
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${BASE}${path}`, init);
  } catch (e) {
    if ((e as { name?: string }).name === 'AbortError') throw e;
    throw new EngineError(0, 'API injoignable');
  }
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const j = (await res.json()) as { detail?: unknown };
      if (typeof j.detail === 'string') detail = j.detail;
    } catch { /* keep the status text */ }
    throw new EngineError(res.status, detail);
  }
  return (await res.json()) as T;
}

const post = <T,>(path: string, body: unknown, signal?: AbortSignal) =>
  request<T>(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal });

export const getMeta = (signal?: AbortSignal) => request<EnginesMeta>('/meta', { signal });
export const assess = (b: AssessRequest, signal?: AbortSignal) => post<AssessResponse>('/assess', b, signal);
export const curve = (b: AssessRequest & { start_hours: number; end_hours: number; points: number }, signal?: AbortSignal) =>
  post<CurveResponse>('/curve', b, signal);
export const getMatrix = (level: CompareLevel, signal?: AbortSignal) =>
  request<MatrixResponse>(`/convergence/matrix?level=${level}`, { signal });
export const getPair = (a: string, b: string, level: CompareLevel, signal?: AbortSignal) =>
  request<PairResponse>(`/convergence/pair?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}&level=${level}`, { signal });
