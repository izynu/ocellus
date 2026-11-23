"use client";

/**
 * The nmap console.
 *
 * A browser cannot run nmap, so this does the honest version of the job: it
 * writes the exact command for the host you are looking at, explains what it
 * answers, and copies it. The live port view beside it reads Shodan's keyless
 * index, which is a real observation of the address from an earlier crawl and is
 * labelled as such.
 *
 * Nothing typed here is sent anywhere but the two public lookups: Google DNS to
 * resolve the name, and Shodan to read the recorded ports. The commands are text.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import {
  NMAP_AUTOMATOR_MODES,
  NMAP_PROFILES,
  nmapAutomatorCommand,
  renderNmap,
} from "@/lib/recon/nmap";
import { runSweep, sweepCommand, type Stage, type SweepResult } from "@/lib/recon/sweep";

type PortView = {
  loading: boolean;
  error: string | null;
  ip: string | null;
  ports: number[];
  hostnames: string[];
  cpes: string[];
  vulns: string[];
  source: string;
};

const EMPTY_PORTS: PortView = {
  loading: false,
  error: null,
  ip: null,
  ports: [],
  hostnames: [],
  cpes: [],
  vulns: [],
  source: "",
};

function normaliseHost(raw: string): string {
  return raw
    .trim()
    .toLowerCase()
    .replace(/^[a-z][a-z0-9+.-]*:\/\//, "")
    .replace(/[/?#].*$/, "")
    .replace(/\.$/, "");
}

function CopyButton({ text }: { text: string }) {
  const [state, setState] = useState<"idle" | "copied" | "selected">("idle");
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const pre = useRef<HTMLPreElement | null>(null);

  useEffect(
    () => () => {
      if (timer.current) clearTimeout(timer.current);
    },
    []
  );

  async function copy() {
    try {
      if (!navigator.clipboard?.writeText) throw new Error("no clipboard");
      await navigator.clipboard.writeText(text);
      setState("copied");
    } catch {
      const el = pre.current;
      if (el) {
        const range = document.createRange();
        range.selectNodeContents(el);
        const sel = window.getSelection();
        sel?.removeAllRanges();
        sel?.addRange(range);
        setState("selected");
      }
    }
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => setState("idle"), 2200);
  }

  return (
    <div>
      <button type="button" className="btn btn-quiet btn-sm" onClick={copy}>
        {state === "copied" ? "Copied" : state === "selected" ? "Press Ctrl+C" : "Copy"}
      </button>
      <span role="status" className="sr-only">
        {state === "copied" ? "Command copied." : state === "selected" ? "Command selected." : ""}
      </span>
      {/* A hidden selectable copy for the clipboard fallback. */}
      <pre ref={pre} aria-hidden="true" style={{ position: "absolute", left: -9999, top: 0 }}>
        {text}
      </pre>
    </div>
  );
}

export function NmapConsole() {
  const [host, setHost] = useState("");
  const [ports, setPorts] = useState<PortView>(EMPTY_PORTS);
  const [sweep, setSweep] = useState<SweepResult | null>(null);
  const [liveStages, setLiveStages] = useState<Stage[]>([]);
  const [sweeping, setSweeping] = useState(false);
  const [sweepError, setSweepError] = useState<string | null>(null);
  const token = useRef(0);

  const target = normaliseHost(host);
  const resolvedIp = ports.ip ?? sweep?.ip ?? "";
  const subnet = resolvedIp
    ? resolvedIp.replace(/\.\d+$/, ".0/24")
    : "192.0.2.0/24";
  const vars = {
    host: target || "example.com",
    ip: resolvedIp || "203.0.113.10",
    subnet,
  };

  /** The full automated sweep: every stage, in nmapAutomator's order. */
  const fullSweep = useCallback(async () => {
    const value = normaliseHost(host);
    if (!value) {
      setSweepError("Enter a hostname or address first.");
      return;
    }
    const mine = ++token.current;
    setSweepError(null);
    setSweep(null);
    setLiveStages([]);
    setSweeping(true);
    try {
      const result = await runSweep(value, (stage) => {
        if (mine === token.current) setLiveStages((prev) => [...prev, stage]);
      });
      if (mine === token.current) setSweep(result);
    } catch {
      if (mine === token.current) setSweepError("The sweep could not finish.");
    } finally {
      if (mine === token.current) setSweeping(false);
    }
  }, [host]);

  const lookup = useCallback(async () => {
    const value = normaliseHost(host);
    if (!value) {
      setPorts({ ...EMPTY_PORTS, error: "Enter a hostname or address first." });
      return;
    }
    const mine = ++token.current;
    setPorts({ ...EMPTY_PORTS, loading: true });
    try {
      const dns = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(value)}&type=A`, {
        credentials: "omit",
      }).then((r) => (r.ok ? r.json() : null));
      const ip: string | null =
        (dns?.Answer as Array<{ type: number; data: string }> | undefined)?.find((a) => a.type === 1)?.data ??
        null;
      if (!ip) {
        if (mine === token.current) {
          setPorts({ ...EMPTY_PORTS, error: "The host did not resolve to an IPv4 address." });
        }
        return;
      }
      const res = await fetch(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`, {
        credentials: "omit",
      });
      if (!res.ok) {
        if (mine === token.current) {
          setPorts({
            ...EMPTY_PORTS,
            ip,
            error:
              res.status === 404
                ? "Shodan has no record for this address."
                : `The index answered ${res.status}.`,
          });
        }
        return;
      }
      const body = (await res.json()) as {
        ports?: number[];
        hostnames?: string[];
        cpes?: string[];
        vulns?: string[];
      };
      if (mine === token.current) {
        setPorts({
          loading: false,
          error: null,
          ip,
          ports: (body.ports ?? []).slice().sort((a, b) => a - b),
          hostnames: (body.hostnames ?? []).slice(0, 30),
          cpes: (body.cpes ?? []).slice(0, 20),
          vulns: (body.vulns ?? []).slice(0, 20),
          source: "internetdb.shodan.io",
        });
      }
    } catch {
      if (mine === token.current) {
        setPorts({ ...EMPTY_PORTS, error: "The lookup could not be read from the browser." });
      }
    }
  }, [host]);

  return (
    <div>
      <div className="box box--raised">
        <label htmlFor="nmap-host" style={{ display: "block", fontSize: 13, fontWeight: 560, marginBottom: 8 }}>
          Target host or address
        </label>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 10 }}>
          <input
            id="nmap-host"
            className="field"
            style={{ flex: "1 1 260px" }}
            type="text"
            inputMode="url"
            autoComplete="off"
            autoCapitalize="none"
            spellCheck={false}
            placeholder="example.com"
            value={host}
            onChange={(e) => setHost(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") void lookup();
            }}
          />
          <button type="button" className="btn btn-primary" onClick={() => void fullSweep()} disabled={sweeping}>
            {sweeping ? "Sweeping…" : "Full automated sweep"}
          </button>
          <button type="button" className="btn btn-quiet" onClick={() => void lookup()} disabled={ports.loading}>
            {ports.loading ? "Looking up…" : "Ports only"}
          </button>
        </div>
        <p className="box__meta" style={{ marginTop: 8 }}>
          The full sweep runs every stage in nmapAutomator's order against public indexes: resolve, name
          service, ownership, observed ports, services, reverse name and HTTP. The port list comes from
          Shodan's index, a crawl at an earlier moment. A live packet scan is the commands below.
        </p>
      </div>

      {sweepError && (
        <p className="tone-warn" role="alert" style={{ marginTop: 10, fontSize: 13.5 }}>
          {sweepError}
        </p>
      )}

      {(sweeping || sweep) && (
        <section className="section-tight" aria-label="Sweep stages">
          <div className="flex flex-wrap items-baseline justify-between gap-3">
            <h3 style={{ fontSize: 17 }}>Sweep of {target}</h3>
            <p className="tabular" style={{ fontSize: 12.5, color: "var(--muted-foreground)" }}>
              {sweep
                ? `${sweep.stages.filter((s) => s.status === "done").length} of ${sweep.stages.length} stages answered in ${(sweep.ms / 1000).toFixed(1)}s`
                : `${liveStages.length} stage${liveStages.length === 1 ? "" : "s"} so far`}
            </p>
          </div>
          <ul className="box-grid box-grid--wide" style={{ marginTop: 12, listStyle: "none", padding: 0 }}>
            {(sweep ? sweep.stages : liveStages).map((s) => {
              const tone =
                s.status === "done" ? "tone-pass" : s.status === "partial" ? "tone-warn" : s.status === "gap" ? "tone-idle" : "tone-info";
              return (
                <li key={s.id} className={`box box--railed land ${tone}`}>
                  <div className="box__head">
                    <span className="dot" aria-hidden="true" />
                    <span className="box__title">{s.title}</span>
                    <span className={`chip ${tone}`} style={{ marginLeft: "auto" }}>
                      {s.status}
                    </span>
                  </div>
                  <p className="box__body">{s.question}</p>
                  {s.facts.length > 0 && (
                    <dl className="facts">
                      {s.facts.slice(0, 12).map((f, i) => (
                        <div key={`${f.label}-${i}`} style={{ display: "contents" }}>
                          <dt>{f.label}</dt>
                          <dd className={f.tone === "bad" ? "tone-warn" : undefined} style={{ overflowWrap: "anywhere" }}>
                            {f.value}
                          </dd>
                        </div>
                      ))}
                    </dl>
                  )}
                  {s.note && (
                    <p className="box__meta" style={{ marginTop: 6, display: "block" }}>
                      {s.note}
                    </p>
                  )}
                  <div className="box__meta" style={{ justifyContent: "space-between" }}>
                    <span className="mono" style={{ fontSize: 11 }}>
                      {s.nmapPhase}
                    </span>
                    <CopyButton text={sweepCommand(sweep?.ip ?? (resolvedIp || null), vars.host, s.id)} />
                  </div>
                </li>
              );
            })}
          </ul>
        </section>
      )}

      {ports.error && (
        <p className="tone-warn" role="alert" style={{ marginTop: 10, fontSize: 13.5 }}>
          {ports.error}
        </p>
      )}

      {ports.ip && !ports.error && (
        <div className="box" style={{ marginTop: 12 }}>
          <div className="box--row">
            <div className="box__main">
              <div className="box__head">
                <span className="dot tone-info" aria-hidden="true" />
                <span className="box__title mono">{ports.ip}</span>
              </div>
              <p className="box__body">
                {ports.ports.length === 0
                  ? "No open port is recorded for this address in the index."
                  : `${ports.ports.length} port${ports.ports.length === 1 ? "" : "s"} observed open.`}
              </p>
              {ports.ports.length > 0 && (
                <p
                  className="mono"
                  style={{ marginTop: 8, fontSize: 12.5, color: "var(--muted-foreground)", overflowWrap: "anywhere" }}
                >
                  {ports.ports.join(", ")}
                </p>
              )}
              {ports.cpes.length > 0 && (
                <p className="box__meta" style={{ marginTop: 6 }}>
                  Products: {ports.cpes.slice(0, 6).join(", ")}
                </p>
              )}
              {ports.vulns.length > 0 && (
                <p className="box__meta tone-warn" style={{ marginTop: 6 }}>
                  CVEs matched: {ports.vulns.slice(0, 6).join(", ")}
                </p>
              )}
            </div>
            <div className="box__aside">
              <span className="chip">{ports.source}</span>
            </div>
          </div>
        </div>
      )}

      <h3 style={{ marginTop: 26, fontSize: 17 }}>Commands for {vars.host}</h3>
      <p className="box__body" style={{ maxWidth: "70ch" }}>
        Each one is the real nmap invocation. Run it on a machine you control, against a host you own or
        are authorised to scan. A command marked loud sends enough traffic to be noticed.
      </p>

      <ul className="box-grid box-grid--wide" style={{ marginTop: 14 }}>
        {NMAP_PROFILES.map((profile) => {
          const command = renderNmap(profile, vars);
          return (
            <li key={profile.id} className={`box ${profile.loud ? "box--railed tone-warn" : ""}`}>
              <div className="box--row">
                <div className="box__main">
                  <div className="box__head">
                    <span className="box__title">{profile.title}</span>
                    {profile.loud && (
                      <span className="chip tone-warn" style={{ marginLeft: "auto" }}>
                        loud
                      </span>
                    )}
                  </div>
                  <p className="box__body">{profile.when}</p>
                  <pre
                    className="mono"
                    style={{
                      marginTop: 10,
                      padding: "8px 10px",
                      background: "var(--muted)",
                      border: "1px solid var(--border)",
                      borderRadius: 8,
                      fontSize: 12,
                      lineHeight: 1.55,
                      whiteSpace: "pre-wrap",
                      wordBreak: "break-all",
                    }}
                  >
                    {command}
                  </pre>
                  <p className="box__meta">
                    <span>{profile.flags}</span>
                    <span>about {profile.time}</span>
                  </p>
                </div>
                <div className="box__aside">
                  <CopyButton text={command} />
                </div>
              </div>
            </li>
          );
        })}
      </ul>

      <h3 style={{ marginTop: 26, fontSize: 17 }}>nmapAutomator</h3>
      <p className="box__body" style={{ maxWidth: "70ch" }}>
        The script that chains the sequence above automatically. Clone it, then run one of these commands.
      </p>
      <ul className="box-grid box-grid--wide" style={{ marginTop: 12 }}>
        {NMAP_AUTOMATOR_MODES.map((mode) => {
          const command = nmapAutomatorCommand(vars.host, mode.mode);
          return (
            <li key={mode.mode} className="box">
              <div className="box--row">
                <div className="box__main">
                  <div className="box__head">
                    <span className="box__title">{mode.label}</span>
                  </div>
                  <p className="box__body">{mode.what}</p>
                  <pre
                    className="mono"
                    style={{
                      marginTop: 10,
                      padding: "8px 10px",
                      background: "var(--muted)",
                      border: "1px solid var(--border)",
                      borderRadius: 8,
                      fontSize: 12,
                      whiteSpace: "pre-wrap",
                      wordBreak: "break-all",
                    }}
                  >
                    {command}
                  </pre>
                </div>
                <div className="box__aside">
                  <CopyButton text={command} />
                </div>
              </div>
            </li>
          );
        })}
      </ul>
      <p className="box__body" style={{ marginTop: 10 }}>
        <a
          href="https://github.com/21y4d/nmapAutomator"
          target="_blank"
          rel="noopener noreferrer"
          style={{ color: "var(--primary)" }}
        >
          nmapAutomator on GitHub
        </a>{" "}
        and{" "}
        <a
          href="https://nmap.org/book/man.html"
          target="_blank"
          rel="noopener noreferrer"
          style={{ color: "var(--primary)" }}
        >
          the nmap reference
        </a>
        .
      </p>
    </div>
  );
}
