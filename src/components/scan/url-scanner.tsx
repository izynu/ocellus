"use client";

/**
 * The URL and file scanner.
 *
 * Two things a browser genuinely can do, and one it cannot.
 *
 * Can, from the page:
 *  - Check a URL against the keyless reputation feeds: Google Safe Browsing and
 *    OpenPhish.
 *  - Read the page through the reader for its final URL, server, title and link
 *    count.
 *  - Hash a file locally with SHA-256 and look the hash up, so the file itself
 *    never leaves the device.
 *
 * Cannot, from the page: run a file through an antivirus engine or a sandbox.
 * The file tab says so rather than implying a scan happened.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import type { FeedVerdict, SanitisedResult } from "@/lib/scan/url-scan";
import { scanUrl } from "@/lib/scan/url-scan";
import { readKey } from "@/lib/scan/keys";

function tone(v: FeedVerdict): string {
  if (v === "listed") return "tone-fail";
  if (v === "clean") return "tone-pass";
  return "tone-idle";
}

function label(v: FeedVerdict): string {
  if (v === "listed") return "Listed";
  if (v === "clean") return "Not listed";
  return "No answer";
}

function UrlTab() {
  const [input, setInput] = useState("");
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<SanitisedResult | null>(null);
  const token = useRef(0);

  const run = useCallback(async () => {
    const value = input.trim();
    if (!value) {
      setError("Enter a URL or hostname to check.");
      return;
    }
    const mine = ++token.current;
    setError(null);
    setResult(null);
    setRunning(true);
    try {
      const res = await scanUrl(value);
      if (mine === token.current) setResult(res);
    } catch (err) {
      if (mine === token.current) {
        setError(err instanceof Error ? err.message : "The check could not run.");
      }
    } finally {
      if (mine === token.current) setRunning(false);
    }
  }, [input]);

  const feeds =
    result === null
      ? []
      : [
          { name: "Google Safe Browsing", answer: result.safeBrowsing },
          { name: "OpenPhish", answer: result.openPhish },
        ];

  const listed = result !== null && (result.safeBrowsing.verdict === "listed" || result.openPhish.verdict === "listed");

  return (
    <div>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void run();
        }}
        noValidate
        style={{ display: "flex", flexWrap: "wrap", gap: 10, alignItems: "center" }}
      >
        <div style={{ flex: "1 1 280px", minWidth: 0 }}>
          <label htmlFor="url-scan-input" className="sr-only">
            URL or hostname to check
          </label>
          <input
            id="url-scan-input"
            className="field"
            type="text"
            inputMode="url"
            autoComplete="url"
            autoCapitalize="none"
            spellCheck={false}
            placeholder="https://example.com/login"
            value={input}
            disabled={running}
            aria-invalid={error ? true : undefined}
            aria-describedby={error ? "url-scan-error" : undefined}
            onChange={(e) => {
              setInput(e.target.value);
              if (error) setError(null);
            }}
          />
        </div>
        {running ? (
          <button
            type="button"
            className="btn btn-quiet"
            onClick={() => {
              token.current++;
              setRunning(false);
            }}
          >
            Cancel
          </button>
        ) : (
          <button type="submit" className="btn btn-primary">
            Check URL
          </button>
        )}
      </form>

      {error && (
        <p id="url-scan-error" role="alert" className="tone-fail" style={{ marginTop: 8, fontSize: 13.5 }}>
          {error}
        </p>
      )}

      {running && (
        <p className="tabular" style={{ marginTop: 12, fontSize: 13, color: "var(--muted-foreground)" }}>
          Asking the reputation feeds and reading the page…
        </p>
      )}

      {result && (
        <div style={{ marginTop: 18 }} className="rise">
          <div className={`box box--railed ${listed ? "tone-fail" : "tone-pass"}`} role="status">
            <div className="box__head">
              <span className="dot" aria-hidden="true" />
              <span className="box__title">{result.host}</span>
              <span className={`chip ${listed ? "tone-fail" : "tone-pass"}`} style={{ marginLeft: "auto" }}>
                {listed ? "Listed" : "Not listed"}
              </span>
            </div>
            <p className="box__body">{result.headline}</p>
          </div>

          <ul className="box-grid box-grid--dense" style={{ marginTop: 12 }}>
            {feeds.map((feed) => (
              <li key={feed.name} className={`box box--railed ${tone(feed.answer.verdict)}`}>
                <div className="box__head">
                  <span className="dot" aria-hidden="true" />
                  <span className="box__title">{feed.name}</span>
                  <span className={`chip ${tone(feed.answer.verdict)}`} style={{ marginLeft: "auto" }}>
                    {label(feed.answer.verdict)}
                  </span>
                </div>
                <p className="box__body">{feed.answer.detail}</p>
              </li>
            ))}
          </ul>

          <dl className="facts" style={{ marginTop: 14 }}>
            <dt>Final URL</dt>
            <dd className="mono">{result.finalUrl || "not read"}</dd>
            <dt>Server</dt>
            <dd>{result.server || "not reported"}</dd>
            <dt>Status</dt>
            <dd>{result.status || "not read"}</dd>
            <dt>Page title</dt>
            <dd>{result.title || "not read"}</dd>
            <dt>Fetch route</dt>
            <dd>{result.via}</dd>
            <dt>Links on the page</dt>
            <dd className="tabular">{result.links.toLocaleString("en-US")}</dd>
            <dt>VirusTotal</dt>
            <dd>
              <a
                href={`https://www.virustotal.com/gui/url/${encodeURIComponent(result.finalUrl || result.host)}`}
                target="_blank"
                rel="noopener noreferrer"
                style={{ color: "var(--primary)" }}
              >
                Open the multi-engine report
              </a>
            </dd>
          </dl>
        </div>
      )}
    </div>
  );
}

function FileTab() {
  const [hash, setHash] = useState<string | null>(null);
  const [name, setName] = useState<string | null>(null);
  const [size, setSize] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [vt, setVt] = useState<{ verdict: FeedVerdict; detail: string } | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);

  async function onFile(file: File) {
    setBusy(true);
    setVt(null);
    try {
      const buffer = await file.arrayBuffer();
      const digest = await crypto.subtle.digest("SHA-256", buffer);
      const hex = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
      setHash(hex);
      setName(file.name);
      setSize(file.size);

      const key = readKey("virustotal");
      if (!key) {
        setVt({
          verdict: "unknown",
          detail:
            "Hash computed locally. Add a VirusTotal key to look the hash up without uploading the file.",
        });
        return;
      }
      try {
        const res = await fetch(`https://www.virustotal.com/api/v3/files/${hex}`, {
          headers: { "x-apikey": key },
          credentials: "omit",
        });
        if (!res.ok) {
          setVt({
            verdict: "unknown",
            detail:
              res.status === 404
                ? "VirusTotal has no record of this hash. A file it has never seen is not necessarily clean."
                : "VirusTotal did not answer for this hash. It sends no cross-origin header, so a browser may be unable to read the lookup.",
          });
          return;
        }
        const body = (await res.json()) as {
          data?: { attributes?: { last_analysis_stats?: { malicious?: number; undetected?: number } } };
        };
        const stats = body.data?.attributes?.last_analysis_stats;
        if (!stats) {
          setVt({ verdict: "unknown", detail: "VirusTotal returned no analysis for this hash." });
          return;
        }
        const bad = stats.malicious ?? 0;
        const total = bad + (stats.undetected ?? 0);
        setVt({
          verdict: bad > 0 ? "listed" : "clean",
          detail: bad > 0 ? `${bad} of ${total} engines flag this file.` : `None of ${total} engines flag this file.`,
        });
      } catch {
        setVt({
          verdict: "unknown",
          detail: "The lookup could not be read from the browser. VirusTotal sends no cross-origin header.",
        });
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <div className="box box--raised" style={{ borderStyle: "dashed", padding: "20px", textAlign: "center" }}>
        <p style={{ fontSize: 15, fontWeight: 560 }}>Hash a file without uploading it</p>
        <p
          style={{
            marginTop: 6,
            fontSize: 13.5,
            color: "var(--muted-foreground)",
            maxWidth: "56ch",
            marginInline: "auto",
          }}
        >
          The file is read in this tab and hashed with SHA-256. Only the hash is used, for a look-up.
          The file never leaves your device.
        </p>
        <input
          ref={inputRef}
          type="file"
          className="sr-only"
          aria-label="Choose a file to hash"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) void onFile(file);
          }}
        />
        <button
          type="button"
          className="btn btn-primary"
          style={{ marginTop: 14 }}
          disabled={busy}
          onClick={() => inputRef.current?.click()}
        >
          {busy ? "Hashing…" : "Choose a file"}
        </button>
      </div>

      {hash && (
        <dl className="facts" style={{ marginTop: 14 }}>
          <dt>File</dt>
          <dd>{name}</dd>
          <dt>Size</dt>
          <dd className="tabular">{size !== null ? `${(size / 1024).toFixed(1)} kB` : "unknown"}</dd>
          <dt>SHA-256</dt>
          <dd className="mono" style={{ wordBreak: "break-all" }}>
            {hash}
          </dd>
          {vt && (
            <>
              <dt>VirusTotal</dt>
              <dd className={vt.verdict === "listed" ? "tone-fail" : vt.verdict === "clean" ? "tone-pass" : undefined}>
                {vt.detail}
              </dd>
            </>
          )}
        </dl>
      )}

      <p className="box__body" style={{ marginTop: 14, maxWidth: "70ch" }}>
        A browser cannot run a file through an antivirus engine or a sandbox. This tab hashes the
        file and checks whether an engine has seen that hash before. For a dynamic analysis,
        submit the file to a sandbox such as ANY.RUN, Joe Sandbox or VirusTotal directly.
      </p>
    </div>
  );
}

export function UrlScanner() {
  const [tab, setTab] = useState<"url" | "file">("url");

  useEffect(() => {
    document.title = tab === "url" ? "URL scanner · Ocellus" : "File hasher · Ocellus";
  }, [tab]);

  return (
    <div>
      <div role="tablist" aria-label="What to scan" className="scroller" style={{ gap: 6 }}>
        <button
          role="tab"
          type="button"
          aria-selected={tab === "url"}
          className={`btn btn-sm ${tab === "url" ? "btn-primary" : "btn-quiet"}`}
          onClick={() => setTab("url")}
        >
          URL
        </button>
        <button
          role="tab"
          type="button"
          aria-selected={tab === "file"}
          className={`btn btn-sm ${tab === "file" ? "btn-primary" : "btn-quiet"}`}
          onClick={() => setTab("file")}
        >
          File hash
        </button>
      </div>

      <div role="tabpanel" aria-label={tab === "url" ? "URL scanner" : "File hasher"} style={{ marginTop: 18 }}>
        {tab === "url" ? <UrlTab /> : <FileTab />}
      </div>
    </div>
  );
}
