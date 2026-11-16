'use client';

import './intelligence.css';
import { useCallback, useEffect, useState } from 'react';
import { EngineError, getMeta, type EnginesMeta } from '@/lib/engines';
import { Atelier } from '@/components/intel/Atelier';
import { ConvergenceMatrix } from '@/components/intel/ConvergenceMatrix';

/**
 * Intelligence workshop: the three scoring engines, driven live through /api/v1/engines.
 * Every number on this page is computed by the backend engines.
 */
export default function IntelligencePage() {
  const [meta, setMeta] = useState<EnginesMeta | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    setError(null);
    getMeta()
      .then(setMeta)
      .catch((e) => setError(e instanceof EngineError && e.status !== 0 ? e.message : 'API injoignable'));
  }, []);
  useEffect(load, [load]);

  return (
    <main className="ix">
      <header>
        <div className="ix-brand">ONYX CTI · Atelier de renseignement</div>
        <h1>Un indicateur perd de sa valeur.<br />Combien, et pourquoi.</h1>
        <p className="ix-lede">Les valeurs ci-dessous sont calculées par les moteurs de décroissance, de confiance et de convergence de la plateforme, à chaque réglage.</p>
      </header>

      {error && (
        <div role="alert" className="ix-alert">
          {error}. Démarrez l&apos;API : <code>cd onyx-api &amp;&amp; uvicorn onyx_api.main:app --port 8000</code>
          <button type="button" onClick={load}>Réessayer</button>
        </div>
      )}
      {!meta && !error && <div className="ix-skeleton" aria-busy="true">Connexion aux moteurs…</div>}
      {meta && (
        <>
          <section aria-labelledby="h-atelier">
            <div className="ix-eyebrow">01 · Atelier</div>
            <h2 id="h-atelier">Modifier un paramètre, lire la conséquence</h2>
            <Atelier meta={meta} />
          </section>
          <section aria-labelledby="h-conv">
            <div className="ix-eyebrow">02 · Convergence</div>
            <h2 id="h-conv">Qui joue la même partition</h2>
            <p className="ix-explain">Similarité de Jaccard sur les techniques ATT&amp;CK documentées de chaque groupe. Seuil de convergence du moteur : {meta.convergence_threshold}.</p>
            <ConvergenceMatrix />
          </section>
        </>
      )}
    </main>
  );
}
