'use client';

import { useEffect, useState } from 'react';
import { EngineError, getMatrix, getPair, type CompareLevel, type MatrixResponse, type PairResponse } from '@/lib/engines';

const LEVELS: { id: CompareLevel; label: string }[] = [
  { id: 'technique', label: 'Techniques et sous-techniques' },
  { id: 'parent', label: 'Techniques parentes' },
];

const shade = (v: number, max: number) => {
  const t = max > 0 ? v / max : 0;
  return `rgb(${Math.round(40 + t * 200)},${Math.round(44 + t * 132)},${Math.round(52 + t * 6)})`;
};

export function ConvergenceMatrix() {
  const [level, setLevel] = useState<CompareLevel>('technique');
  const [data, setData] = useState<MatrixResponse | null>(null);
  const [sel, setSel] = useState<{ i: number; j: number } | null>(null);
  const [pair, setPair] = useState<PairResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const ctrl = new AbortController();
    setData(null); setSel(null); setPair(null); setError(null);
    getMatrix(level, ctrl.signal)
      .then(setData)
      .catch((e) => { if ((e as { name?: string }).name !== 'AbortError') setError(e instanceof EngineError ? e.message : 'Erreur inattendue'); });
    return () => ctrl.abort();
  }, [level]);

  useEffect(() => {
    if (!data || !sel) { setPair(null); return; }
    const ctrl = new AbortController();
    getPair(data.actors[sel.i].name, data.actors[sel.j].name, level, ctrl.signal)
      .then(setPair)
      .catch((e) => { if ((e as { name?: string }).name !== 'AbortError') setError(e instanceof EngineError ? e.message : 'Erreur inattendue'); });
    return () => ctrl.abort();
  }, [sel, data, level]);

  const n = data?.actors.length ?? 0;
  return (
    <div>
      <div className="ix-controls">
        <div className="ix-seg" role="group" aria-label="Niveau de comparaison">
          {LEVELS.map((l) => (
            <button key={l.id} type="button" aria-pressed={level === l.id} onClick={() => setLevel(l.id)}>{l.label}</button>
          ))}
        </div>
        {data && (
          <span className="ix-dim">
            Maximum observé : {data.max_offdiagonal.toFixed(2)} (seuil {data.threshold}).{' '}
            {data.pairs_at_or_above_threshold === 0 ? 'Aucune paire n’atteint le seuil.' : `${data.pairs_at_or_above_threshold} paire(s) au-dessus.`}
          </span>
        )}
      </div>
      {error && <div role="alert" className="ix-alert">{error}</div>}
      {!data && !error && <div className="ix-skeleton" aria-busy="true">Chargement de la matrice…</div>}
      {data && (
        <div className="ix-panel">
          <div className="ix-heat" style={{ gridTemplateColumns: `110px repeat(${n}, minmax(0, 1fr))` }}>
            <div />
            {data.actors.map((a) => <div key={a.name} className="ix-collab">{a.name}</div>)}
            {data.actors.map((a, i) => (
              <Row key={a.name} name={a.name}>
                {data.matrix[i].map((v, j) =>
                  i === j ? (
                    <div key={j} className="ix-cell ix-diag" aria-hidden="true">{a.count}</div>
                  ) : (
                    <button
                      key={j} type="button"
                      className={`ix-cell${v >= data.threshold ? ' ix-conv' : ''}${sel?.i === i && sel?.j === j ? ' ix-sel' : ''}`}
                      style={{ background: shade(v, data.max_offdiagonal) }}
                      aria-label={`${a.name} contre ${data.actors[j].name} : ${v.toFixed(2)}`}
                      onClick={() => setSel({ i, j })}
                    >{Math.round(v * 100)}</button>
                  ),
                )}
              </Row>
            ))}
          </div>
          <p className="ix-detail" aria-live="polite">
            {pair ? (
              <>
                <b>{pair.a}</b> et <b>{pair.b}</b> : Jaccard <b>{pair.jaccard.toFixed(2)}</b> · {pair.shared.length} communes,{' '}
                {pair.only_a.length} propres à {pair.a}, {pair.only_b.length} propres à {pair.b} ·{' '}
                {pair.convergent ? <b>convergence au sens du moteur</b> : `sous le seuil de ${pair.threshold}`}.<br />
                {pair.shared.length ? pair.shared.join(', ') : 'Aucune technique commune.'}
              </>
            ) : 'Sélectionnez une cellule pour voir les techniques partagées.'}
          </p>
        </div>
      )}
    </div>
  );
}

function Row({ name, children }: { name: string; children: React.ReactNode }) {
  return (<><div className="ix-rowlab">{name}</div>{children}</>);
}
