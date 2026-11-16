'use client';

import { useEffect, useMemo, useState } from 'react';
import {
  assess, curve, EngineError,
  type AssessRequest, type AssessResponse, type CurveResponse, type EnginesMeta, type WeightKey,
} from '@/lib/engines';
import { DecayStateBadge } from './DecayStateBadge';

const WEIGHT_LABEL: Record<WeightKey, string> = {
  source: 'Source', corroboration: 'Corroboration', freshness: 'Fraîcheur', context: 'Contexte', analyst: 'Analyste',
};
const WEIGHT_COLOR: Record<WeightKey, string> = {
  source: '#f0b03a', corroboration: '#7fa6d8', freshness: '#78c79a', context: '#d9824a', analyst: '#8d9099',
};
const WEIGHT_KEYS = Object.keys(WEIGHT_LABEL) as WeightKey[];

const fmtAge = (h: number) => (h < 48 ? `${Math.round(h)} h` : `${(h / 24).toFixed(1)} j`);

/** Normalise raw slider values to weights that sum to exactly 1 (the engine rejects anything else). */
function normalise(raw: Record<WeightKey, number>): Record<WeightKey, number> {
  const sum = WEIGHT_KEYS.reduce((a, k) => a + raw[k], 0) || 1;
  const out = {} as Record<WeightKey, number>;
  let acc = 0;
  WEIGHT_KEYS.forEach((k, i) => {
    out[k] = i === WEIGHT_KEYS.length - 1 ? Math.max(0, 1 - acc) : raw[k] / sum;
    acc += out[k];
  });
  return out;
}

export function Atelier({ meta }: { meta: EnginesMeta }) {
  const [iocType, setIocType] = useState('ipv4');
  const [host, setHost] = useState('dedicated_criminal');
  const [tld, setTld] = useState('.xyz');
  const [age, setAge] = useState(24);
  const [source, setSource] = useState(meta.sources['circl_misp'] !== undefined ? 'circl_misp' : Object.keys(meta.sources)[0]);
  const [n, setN] = useState(1);
  const [contested, setContested] = useState(false);
  const [certainty, setCertainty] = useState(0.5);
  const [override, setOverride] = useState(false);
  const [overrideScore, setOverrideScore] = useState(80);
  const [rawW, setRawW] = useState<Record<WeightKey, number>>(
    () => Object.fromEntries(WEIGHT_KEYS.map((k) => [k, Math.round(meta.default_weights[k] * 100)])) as Record<WeightKey, number>,
  );

  const [result, setResult] = useState<AssessResponse | null>(null);
  const [series, setSeries] = useState<CurveResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(true);

  const weights = useMemo(() => normalise(rawW), [rawW]);
  const windowH = Math.max(72, Math.round(age * 2));

  const request = useMemo<AssessRequest>(() => {
    const r: AssessRequest = { ioc_type: iocType, hours_since_seen: age, source, corroboration_count: n, weights };
    if (iocType === 'ipv4' || iocType === 'ipv6') r.host_type = host;
    if (iocType === 'domain') r.tld = tld;
    if (iocType === 'cve') r.exploit_available = true;
    if (contested) { r.contested = true; r.contestation_certainty = certainty; }
    if (override) r.analyst_override_score = overrideScore;
    return r;
  }, [iocType, host, tld, age, source, n, contested, certainty, override, overrideScore, weights]);

  // Debounced, cancellable: a stale response can never overwrite a newer one.
  useEffect(() => {
    const ctrl = new AbortController();
    setPending(true);
    const t = setTimeout(async () => {
      try {
        const [a, c] = await Promise.all([
          assess(request, ctrl.signal),
          curve({ ...request, start_hours: 0, end_hours: windowH, points: 121 }, ctrl.signal),
        ]);
        setResult(a); setSeries(c); setError(null);
      } catch (e) {
        if ((e as { name?: string }).name === 'AbortError') return;
        setError(e instanceof EngineError ? e.message : 'Erreur inattendue');
      } finally {
        if (!ctrl.signal.aborted) setPending(false);
      }
    }, 140);
    return () => { clearTimeout(t); ctrl.abort(); };
  }, [request, windowH]);

  return (
    <div className="ix-atelier">
      <form className="ix-panel ix-form" onSubmit={(e) => e.preventDefault()} aria-label="Paramètres de l'indicateur">
        <fieldset>
          <legend>Indicateur</legend>
          <label>Type
            <select value={iocType} onChange={(e) => setIocType(e.target.value)}>
              {meta.ioc_types.map((t) => <option key={t}>{t}</option>)}
            </select>
          </label>
          {(iocType === 'ipv4' || iocType === 'ipv6') && (
            <label>Type d&apos;hébergeur
              <select value={host} onChange={(e) => setHost(e.target.value)}>
                {meta.host_types.map((t) => <option key={t}>{t}</option>)}
              </select>
            </label>
          )}
          {iocType === 'domain' && (
            <label>TLD
              <select value={tld} onChange={(e) => setTld(e.target.value)}>
                {meta.tlds.map((t) => <option key={t}>{t}</option>)}
              </select>
            </label>
          )}
          <label>Âge de la dernière observation : {fmtAge(age)}
            <input type="range" min={0} max={720} value={age} onChange={(e) => setAge(+e.target.value)} />
          </label>
        </fieldset>
        <fieldset>
          <legend>Source et preuves</legend>
          <label>Source
            <select value={source} onChange={(e) => setSource(e.target.value)}>
              {Object.entries(meta.sources).map(([k, v]) => <option key={k} value={k}>{`${k} (${v.toFixed(2)})`}</option>)}
            </select>
          </label>
          <label>Sources indépendantes : {n}
            <input type="range" min={1} max={8} value={n} onChange={(e) => setN(+e.target.value)} />
          </label>
          <label className="ix-check"><input type="checkbox" checked={contested} onChange={(e) => setContested(e.target.checked)} />Attribution contestée</label>
          <label aria-disabled={!contested}>Certitude d&apos;attribution : {certainty.toFixed(2)}
            <input type="range" min={0} max={1} step={0.05} value={certainty} disabled={!contested} onChange={(e) => setCertainty(+e.target.value)} />
          </label>
          <label className="ix-check"><input type="checkbox" checked={override} onChange={(e) => setOverride(e.target.checked)} />Note analyste imposée</label>
          <label aria-disabled={!override}>Note : {overrideScore}
            <input type="range" min={0} max={100} value={overrideScore} disabled={!override} onChange={(e) => setOverrideScore(+e.target.value)} />
          </label>
        </fieldset>
        <fieldset>
          <legend>Poids du score (normalisés)</legend>
          {WEIGHT_KEYS.map((k) => (
            <label key={k}>{WEIGHT_LABEL[k]} : {Math.round(weights[k] * 100)} %
              <input type="range" min={0} max={100} value={rawW[k]} onChange={(e) => setRawW({ ...rawW, [k]: +e.target.value })} />
            </label>
          ))}
        </fieldset>
      </form>

      <div className="ix-out" aria-busy={pending}>
        {error && <div role="alert" className="ix-alert">{error}</div>}
        <div className="ix-panel">
          <DecayChart series={series} age={age} windowH={windowH} decayNow={result?.decay} />
          <div className="ix-kpis">
            <span>Fraîcheur<b>{result ? result.decay.toFixed(2) : '–'}</b></span>
            <span>État<b className="ix-small">{result ? <DecayStateBadge state={result.state} /> : '–'}</b></span>
            <span>Première heure sous 0,5<b>{series ? (series.first_hour_at_or_below_half === null ? 'hors fenêtre' : fmtAge(series.first_hour_at_or_below_half)) : '–'}</b></span>
          </div>
        </div>
        <div className="ix-panel">
          <div className="ix-kpis">
            <span>Confiance composite<b>{result ? Math.round(result.composite * 100) : '–'}</b></span>
            {result && result.contestation_penalty < 1 && <span>Malus d&apos;attribution contestée<b>×{result.contestation_penalty.toFixed(2)}</b></span>}
          </div>
          <div className="ix-stack" role="img" aria-label="Contribution de chaque composante au score">
            {result?.components.map((c) => (
              <i key={c.name} title={`${WEIGHT_LABEL[c.name]} ${Math.round(c.contribution * 100)}`} style={{ width: `${c.contribution * 100}%`, background: WEIGHT_COLOR[c.name] }} />
            ))}
          </div>
          <table className="ix-table">
            <thead><tr><th>Composante</th><th>Poids</th><th>Valeur</th><th>Contribution</th></tr></thead>
            <tbody>
              {result?.components.map((c) => (
                <tr key={c.name}>
                  <td><i className="ix-swatch" style={{ background: WEIGHT_COLOR[c.name] }} />{WEIGHT_LABEL[c.name]}</td>
                  <td>{Math.round(c.weight * 100)} %</td><td>{c.value.toFixed(2)}</td><td>{(c.contribution * 100).toFixed(1)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {result && (
            <p className="ix-note">
              {!result.source_known && 'Source inconnue de la table : fiabilité par défaut (0,15). '}
              {result.analyst_component_derived
                ? 'Sans note analyste, cette composante est la moyenne de la fiabilité de la source et de la fraîcheur.'
                : 'Note analyste imposée.'}
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

function DecayChart({ series, age, windowH, decayNow }: { series: CurveResponse | null; age: number; windowH: number; decayNow?: number }) {
  const W = 700, H = 250, m = { l: 40, r: 12, t: 12, b: 28 };
  const pw = W - m.l - m.r, ph = H - m.t - m.b;
  const x = (h: number) => m.l + (h / windowH) * pw;
  const y = (v: number) => m.t + (1 - v) * ph;
  const path = series ? series.points.map((p, i) => `${i ? 'L' : 'M'}${x(p.hours).toFixed(1)} ${y(p.decay).toFixed(1)}`).join('') : '';
  return (
    <svg viewBox={`0 0 ${W} ${H}`} width="100%" role="img" aria-label="Décroissance de l'indicateur sélectionné" className="ix-chart">
      {[0.8, 0.5, 0.15].map((v) => (
        <g key={v}><line x1={m.l} x2={W - m.r} y1={y(v)} y2={y(v)} className="ix-grid" /><text x={m.l - 6} y={y(v) + 3} textAnchor="end">{v.toFixed(2)}</text></g>
      ))}
      <text x={m.l - 6} y={y(1) + 3} textAnchor="end">1.00</text>
      {[0, 1, 2, 3, 4].map((i) => (
        <text key={i} x={x((windowH * i) / 4)} y={H - 8} textAnchor={i === 4 ? 'end' : 'middle'}>{fmtAge(Math.round((windowH * i) / 4))}</text>
      ))}
      {path && <path d={path} fill="none" stroke="#f0b03a" strokeWidth={2} />}
      {decayNow !== undefined && age <= windowH && (
        <g><line x1={x(age)} x2={x(age)} y1={m.t} y2={H - m.b} className="ix-marker" /><circle cx={x(age)} cy={y(decayNow)} r={4.5} fill="#e9e5da" /></g>
      )}
    </svg>
  );
}
