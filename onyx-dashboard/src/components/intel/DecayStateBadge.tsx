import type { DecayState } from '@/lib/engines';

/** State is encoded twice (shape + color) and always accompanied by its label. */
const SPEC: Record<DecayState, { label: string; color: string; path: string; hollow?: boolean }> = {
  valid: { label: 'Valide', color: '#78c79a', path: 'M6 1a5 5 0 1 0 0 10A5 5 0 0 0 6 1z' },
  degrading: { label: 'En dégradation', color: '#f0b03a', path: 'M6 1 11 11H1z' },
  stale: { label: 'Périmé', color: '#d9824a', path: 'M1 1h10v10H1z' },
  obsolete: { label: 'Obsolète', color: '#6a6e77', path: 'M6 1 11 6 6 11 1 6z', hollow: true },
};

export function DecayStateBadge({ state }: { state: DecayState }) {
  const s = SPEC[state] ?? SPEC.obsolete;
  return (
    <span className="ix-state">
      <svg viewBox="0 0 12 12" width={11} height={11} aria-hidden="true">
        <path d={s.path} fill={s.hollow ? 'none' : s.color} stroke={s.color} strokeWidth={s.hollow ? 1.6 : 0} />
      </svg>
      {s.label}
    </span>
  );
}
