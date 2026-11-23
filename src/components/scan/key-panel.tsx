"use client";

/**
 * The key panel.
 *
 * A few sources cannot be read without a key, and a static page has no business
 * shipping one. This panel is the answer: the visitor brings their own, it is
 * stored in this browser only, and the checks that need it run against the real
 * service. Removing a key removes it immediately.
 *
 * The panel is explicit about what a key unlocks and what it does not. VirusTotal
 * is listed with the truth: its API sends no cross-origin header, so even a
 * valid key cannot be read from a page. Showing that here is better than letting
 * someone paste a key and wonder why nothing changed.
 */

import { useEffect, useState } from "react";
import {
  KEYED_PROVIDERS,
  clearKey,
  looksLikeKey,
  readKey,
  storageAvailable,
  writeKey,
  type KeyedProvider,
} from "@/lib/scan/keys";

/** Providers whose browser read actually works, confirmed by a preflight. */
const BROWSER_READABLE: Record<KeyedProvider, boolean> = {
  shodan: true,
  urlscan: true,
  censys: true,
  virustotal: false,
};

const NOT_READABLE_NOTE =
  "Its API sends no Access-Control-Allow-Origin header, so a page cannot read even an authenticated answer. A key here is stored but cannot be used by the scan.";

export function KeyPanel({ compact = false }: { compact?: boolean }) {
  const [values, setValues] = useState<Record<string, string>>({});
  const [saved, setSaved] = useState<Record<string, boolean>>({});
  const [supported, setSupported] = useState(true);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    setSupported(storageAvailable());
    const next: Record<string, string> = {};
    for (const provider of KEYED_PROVIDERS) next[provider.id] = readKey(provider.id) ?? "";
    setValues(next);
  }, []);

  function save(provider: KeyedProvider) {
    const value = values[provider] ?? "";
    const ok = writeKey(provider, value);
    setSaved((s) => ({ ...s, [provider]: ok }));
    setSupported(ok || storageAvailable());
  }

  function remove(provider: KeyedProvider) {
    clearKey(provider);
    setValues((v) => ({ ...v, [provider]: "" }));
    setSaved((s) => ({ ...s, [provider]: true }));
  }

  const stored = KEYED_PROVIDERS.filter((p) => (values[p.id] ?? "").trim()).length;

  return (
    <section className="box box--raised" aria-labelledby="keys-heading">
      <div className="box--row">
        <div className="box__main">
          <h2 id="keys-heading" className="box__title" style={{ fontSize: 15 }}>
            Bring your own keys
          </h2>
          <p className="box__body" style={{ maxWidth: "68ch" }}>
            Four sources need a key. Yours is stored in this browser and sent only to the service
            it belongs to. It is never uploaded here, never written into a report, and never put in
            a URL. {stored > 0 ? `${stored} stored.` : "None stored yet."}
          </p>
        </div>
        <div className="box__aside">
          <button
            type="button"
            className="btn btn-quiet btn-sm"
            aria-expanded={open}
            aria-controls="keys-body"
            onClick={() => setOpen((v) => !v)}
          >
            {open ? "Hide" : "Manage keys"}
          </button>
        </div>
      </div>

      {!compact && !open && stored === 0 && (
        <p className="box__meta">
          Shodan, Censys and urlscan work from the browser with a key. VirusTotal does not, and says so.
        </p>
      )}

      <div id="keys-body" hidden={!open} style={{ marginTop: 14 }}>
        {!supported && (
          <p className="chip chip--wrap tone-warn" style={{ marginBottom: 12 }}>
            This browser blocks storage, so a key cannot be kept between page loads. The scan still runs without one.
          </p>
        )}

        <ul className="box-grid box-grid--wide" style={{ listStyle: "none", padding: 0 }}>
          {KEYED_PROVIDERS.map((provider) => {
            const readable = BROWSER_READABLE[provider.id];
            const value = values[provider.id] ?? "";
            const valid = looksLikeKey(provider.id, value);
            return (
              <li key={provider.id} className="box">
                <div className="box__head">
                  <span className="box__title">{provider.name}</span>
                  <span
                    className={`chip ${readable ? "tone-pass" : "tone-warn"}`}
                    style={{ marginLeft: "auto" }}
                    title={readable ? "A key works in the browser" : "A key cannot be read in the browser"}
                  >
                    {readable ? "Works with a key" : "Key cannot be read"}
                  </span>
                </div>
                <p className="box__body">{provider.unlocks}</p>
                <p className="box__meta">
                  <a href={provider.url} target="_blank" rel="noopener noreferrer" style={{ color: "var(--primary)" }}>
                    Get a key
                  </a>
                  <span>{provider.tier}</span>
                </p>
                {!readable && <p className="box__body tone-warn">{NOT_READABLE_NOTE}</p>}

                <div className="flex flex-wrap gap-2" style={{ marginTop: 10 }}>
                  <label htmlFor={`key-${provider.id}`} className="sr-only">
                    {provider.name} key
                  </label>
                  <input
                    id={`key-${provider.id}`}
                    className="field"
                    style={{ flex: "1 1 180px", height: 38, fontSize: 13 }}
                    type="password"
                    autoComplete="off"
                    spellCheck={false}
                    placeholder={provider.id === "censys" ? "api-id:api-secret" : "Paste key"}
                    value={value}
                    onChange={(e) => setValues((v) => ({ ...v, [provider.id]: e.target.value }))}
                  />
                  <button type="button" className="btn btn-quiet btn-sm" onClick={() => save(provider.id)} disabled={!supported}>
                    Save
                  </button>
                  {value && (
                    <button type="button" className="btn btn-ghost btn-sm" onClick={() => remove(provider.id)}>
                      Remove
                    </button>
                  )}
                </div>
                {saved[provider.id] && value && (
                  <p className={`box__meta ${valid ? "tone-pass" : "tone-warn"}`} role="status">
                    {valid ? "Saved in this browser." : "Saved, but it does not look like this service's key format."}
                  </p>
                )}
              </li>
            );
          })}
        </ul>
      </div>
    </section>
  );
}
