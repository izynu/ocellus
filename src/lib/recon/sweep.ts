/**
 * The automated multi-stage host sweep.
 *
 * This is the nmapAutomator idea, made honest. nmapAutomator runs a fixed
 * sequence of nmap phases: host discovery, top ports, full TCP, service and
 * version, scripts, UDP, then vulnerability checks. A browser cannot send a
 * packet, so it cannot run any of the active phases. What it can do is run the
 * same sequence against every public index that records what an active scan
 * would have found, in the same order, and report each stage the way a scan
 * reports one.
 *
 * So each stage here is a real query with a real answer or a real gap:
 *
 *   1. Resolve       A and AAAA, from DNS over HTTPS.
 *   2. Name service  NS records, so the zone's own servers are named.
 *   3. Ownership     The announcing network, from RIPEstat and the registry.
 *   4. Observed ports  Shodan's keyless index, the closest thing to a port scan
 *                      a page can read. It is a past crawl and is labelled so.
 *   5. Services      Product and CVE ids matched to the address by the same index.
 *   6. Reverse        Whatever name the address answers to.
 *   7. HTTP           The headers of the web service on 443, if one answers.
 *
 * The result is a stage list with a status each, exactly like the main scan, and
 * the matching nmap command for the stages the browser could only approximate.
 * Every stage that could not be run says so; nothing is inferred.
 */

export type StageStatus = "done" | "partial" | "gap" | "running";

export type Stage = {
  id: string;
  title: string;
  /** The question the stage asks. */
  question: string;
  /** The nmap phase this stands in for, when it stands in for one. */
  nmapPhase: string;
  status: StageStatus;
  /** The lines of fact the stage produced. */
  facts: Array<{ label: string; value: string; tone?: "good" | "bad" }>;
  note?: string;
};

export type SweepResult = {
  host: string;
  ip: string | null;
  stages: Stage[];
  startedAt: string;
  finishedAt: string;
  ms: number;
};

const EMPTY_STAGE = (id: string, title: string, question: string, nmapPhase: string): Stage => ({
  id,
  title,
  question,
  nmapPhase,
  status: "running",
  facts: [],
});

function stage(
  id: string,
  title: string,
  question: string,
  nmapPhase: string,
  status: StageStatus,
  facts: Stage["facts"],
  note?: string
): Stage {
  return { id, title, question, nmapPhase, status, facts, note };
}

/** Resolve a name to its addresses through DNS over HTTPS. */
async function resolve(host: string): Promise<{ a: string[]; aaaa: string[]; failed: boolean }> {
  const ask = async (type: string): Promise<{ values: string[]; failed: boolean }> => {
    try {
      const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(host)}&type=${type}`, {
        credentials: "omit",
      });
      if (!res.ok) return { values: [], failed: true };
      const body = (await res.json()) as {
        Status?: number;
        Answer?: Array<{ type: number; data: string }>;
      };
      const wanted = type === "A" ? 1 : 28;
      return {
        values: (body.Answer ?? []).filter((r) => r.type === wanted).map((r) => r.data),
        failed: false,
      };
    } catch {
      return { values: [], failed: true };
    }
  };
  const [a, aaaa] = await Promise.all([ask("A"), ask("AAAA")]);
  return { a: a.values, aaaa: aaaa.values, failed: a.failed && aaaa.failed };
}

export async function runSweep(rawHost: string, onStage?: (s: Stage) => void): Promise<SweepResult> {
  const started = Date.now();
  const host = rawHost
    .trim()
    .toLowerCase()
    .replace(/^[a-z][a-z0-9+.-]*:\/\//, "")
    .replace(/[/?#].*$/, "")
    .replace(/\.$/, "");

  const stages: Stage[] = [];
  const push = (s: Stage) => {
    stages.push(s);
    onStage?.(s);
  };

  // 1. Resolve
  const res = await resolve(host);
  const ip = res.a[0] ?? null;
  if (res.failed) {
    push(
      stage("resolve", "Resolve", "What addresses does the name have?", "Host discovery (-sn)", "gap", [], "The resolver did not answer. That is not evidence that no address exists.")
    );
  } else if (!ip && res.aaaa.length === 0) {
    push(stage("resolve", "Resolve", "What addresses does the name have?", "Host discovery (-sn)", "gap", [], "The name resolved to no address. It may not exist, or may be IPv6-only behind a filter."));
  } else {
    push(
      stage("resolve", "Resolve", "What addresses does the name have?", "Host discovery (-sn)", "done", [
        ...(ip ? [{ label: "IPv4", value: ip }] : []),
        ...res.aaaa.map((v) => ({ label: "IPv6", value: v })),
      ])
    );
  }

  // 2. Name service
  try {
    const nsRes = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(host)}&type=NS`, {
      credentials: "omit",
    });
    const ns = nsRes.ok
      ? (((await nsRes.json()) as { Answer?: Array<{ type: number; data: string }> }).Answer ?? [])
          .filter((r) => r.type === 2)
          .map((r) => r.data)
      : [];
    push(
      stage(
        "ns",
        "Name service",
        "Which servers answer for the zone?",
        "DNS brute force (-sU:53, script dns-*)",
        ns.length > 0 ? "done" : "partial",
        ns.slice(0, 8).map((n) => ({ label: "NS", value: n })),
        ns.length === 0 ? "No NS record was returned; the zone may be delegated or the resolver may have answered from cache." : undefined
      )
    );
  } catch {
    push(stage("ns", "Name service", "Which servers answer for the zone?", "DNS", "gap", [], "The NS lookup could not be read from the browser."));
  }

  // 3. Ownership, from the address
  if (ip) {
    try {
      const [ripe, who] = await Promise.all([
        fetch(`https://stat.ripe.net/data/prefix-overview/data.json?resource=${encodeURIComponent(ip)}`, {
          credentials: "omit",
        }).then((r) => (r.ok ? r.json() : null)),
        fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, { credentials: "omit" }).then((r) =>
          r.ok ? r.json() : null
        ),
      ]);
      const facts: Stage["facts"] = [];
      const asns = (ripe?.data?.asns ?? []) as Array<{ asn?: number; holder?: string }>;
      if (asns[0]?.asn) facts.push({ label: "ASN", value: `AS${asns[0].asn}${asns[0].holder ? ` ${asns[0].holder}` : ""}` });
      if (ripe?.data?.resource) facts.push({ label: "Prefix", value: String(ripe.data.resource) });
      if (who?.org) facts.push({ label: "Owner", value: String(who.org) });
      if (who?.city || who?.country) facts.push({ label: "Location", value: [who.city, who.country].filter(Boolean).join(", ") });
      push(
        stage(
          "ownership",
          "Ownership",
          "Which network announces the address?",
          "Traceroute and ASN lookup (--traceroute)",
          facts.length > 0 ? "done" : "partial",
          facts,
          facts.length === 0 ? "Neither the registry nor the geolocation source named the network." : undefined
        )
      );
    } catch {
      push(stage("ownership", "Ownership", "Which network announces the address?", "ASN lookup", "gap", [], "The ownership sources could not be read."));
    }

    // 4 and 5. Observed ports and services, from the keyless index.
    try {
      const r = await fetch(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`, { credentials: "omit" });
      if (!r.ok) {
        const why = r.status === 404 ? "The index holds no record for this address." : `The index answered ${r.status}.`;
        push(stage("ports", "Observed ports", "Which ports has an outside index seen open?", "Top ports (-sS --top-ports 1000)", "gap", [], why));
        push(stage("services", "Services", "Which products and CVEs match the banners?", "Service and version (-sV -sC)", "gap", [], why));
      } else {
        const body = (await r.json()) as {
          ports?: number[];
          hostnames?: string[];
          cpes?: string[];
          vulns?: string[];
        };
        const raw = body.ports ?? [];
        // The index lists ports for both address families under one key. A value
        // above 65535 is an IPv6 address encoded as an integer, not a port, so it
        // is filtered out rather than shown as "port 2606".
        const ports = raw.filter((p) => Number.isFinite(p) && p > 0 && p <= 65535).slice().sort((a, b) => a - b);
        push(
          stage(
            "ports",
            "Observed ports",
            "Which ports has an outside index seen open?",
            "Top ports (-sS --top-ports 1000)",
            ports.length > 0 ? "done" : "partial",
            ports.map((p) => ({ label: String(p), value: portName(p) })),
            "This is a crawl at an earlier moment, not a scan of the host now."
          )
        );
        const services: Stage["facts"] = [
          ...(body.cpes ?? []).slice(0, 10).map((c) => ({ label: "CPE", value: c })),
          ...(body.vulns ?? []).slice(0, 10).map((v) => ({ label: "CVE", value: v, tone: "bad" as const })),
        ];
        push(
          stage(
            "services",
            "Services",
            "Which products and CVEs match the banners?",
            "Service and version (-sV -sC)",
            services.length > 0 ? "done" : "partial",
            services,
            services.length === 0 ? "The index records no product or CVE against this address." : "CVE ids are matched on a version string, not confirmed as exploitable."
          )
        );
      }
    } catch {
      push(stage("ports", "Observed ports", "Which ports has an outside index seen open?", "Top ports", "gap", [], "The index could not be read from the browser."));
      push(stage("services", "Services", "Which products and CVEs match the banners?", "Service and version", "gap", [], "The index could not be read from the browser."));
    }

    // 6. Reverse name
    try {
      const ptr = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(ip)}&type=PTR`, {
        credentials: "omit",
      });
      const names = ptr.ok
        ? (((await ptr.json()) as { Answer?: Array<{ type: number; data: string }> }).Answer ?? [])
            .filter((a) => a.type === 12)
            .map((a) => a.data.replace(/\.$/, ""))
        : [];
      // DoH does not reverse an IPv4 literal automatically; ask the arpa name.
      const arpa = ip.split(".").reverse().join(".") + ".in-addr.arpa";
      const ptr2 = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(arpa)}&type=PTR`, {
        credentials: "omit",
      });
      const names2 = ptr2.ok
        ? (((await ptr2.json()) as { Answer?: Array<{ type: number; data: string }> }).Answer ?? [])
            .filter((a) => a.type === 12)
            .map((a) => a.data.replace(/\.$/, ""))
        : [];
      const all = [...new Set([...names, ...names2])];
      push(
        stage(
          "reverse",
          "Reverse name",
          "What name does the address answer to?",
          "Reverse DNS (script dns-ptr)",
          all.length > 0 ? "done" : "partial",
          all.slice(0, 6).map((n) => ({ label: "PTR", value: n })),
          all.length === 0 ? "The address publishes no PTR record." : undefined
        )
      );
    } catch {
      push(stage("reverse", "Reverse name", "What name does the address answer to?", "Reverse DNS", "gap", [], "The reverse lookup could not be read."));
    }
  } else {
    for (const [id, title, q, phase] of [
      ["ownership", "Ownership", "Which network announces the address?", "ASN lookup"],
      ["ports", "Observed ports", "Which ports has an outside index seen open?", "Top ports"],
      ["services", "Services", "Which products and CVEs match the banners?", "Service and version"],
      ["reverse", "Reverse name", "What name does the address answer to?", "Reverse DNS"],
    ] as const) {
      push(stage(id, title, q, phase, "gap", [], "No IPv4 address to look up."));
    }
  }

  // 7. HTTP, from the header proxy that answers a browser.
  try {
    const h = await fetch(`https://api.hackertarget.com/httpheaders/?q=${encodeURIComponent(host)}`, {
      credentials: "omit",
    }).then((r) => (r.ok ? r.text() : null));
    const usable = h && !/error|quota|exceeded/i.test(h);
    const server = usable ? (h.match(/server:\s*([^\r\n]+)/i)?.[1]?.trim() ?? "") : "";
    const statusLine = usable ? (h.match(/HTTP\/[\d.]+\s+(\d{3})/)?.[1] ?? "") : "";
    const powered = usable ? (h.match(/x-powered-by:\s*([^\r\n]+)/i)?.[1]?.trim() ?? "") : "";
    push(
      stage(
        "http",
        "HTTP service",
        "What does the web server on 443 say about itself?",
        "HTTP scripts (--script http-*)",
        usable ? "done" : "gap",
        [
          ...(statusLine ? [{ label: "Status", value: statusLine }] : []),
          ...(server ? [{ label: "Server", value: server }] : []),
          ...(powered ? [{ label: "Powered by", value: powered }] : []),
        ],
        usable
          ? undefined
          : "The header source returned a quota message rather than a response, so nothing is claimed about the web service."
      )
    );
  } catch {
    push(stage("http", "HTTP service", "What does the web server on 443 say about itself?", "HTTP scripts", "gap", [], "The header source could not be read."));
  }

  const finished = Date.now();
  return {
    host,
    ip,
    stages,
    startedAt: new Date(started).toISOString(),
    finishedAt: new Date(finished).toISOString(),
    ms: finished - started,
  };
}

/** Common service names, so a port list reads as a service list. */
function portName(port: number): string {
  const names: Record<number, string> = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "Submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    2375: "Docker",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP alt",
    8443: "HTTPS alt",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
  };
  return names[port] ?? "open";
}

/** The nmap command that reproduces a stage for real. */
export function sweepCommand(ip: string | null, host: string, id: string): string {
  const target = ip ?? host;
  switch (id) {
    case "resolve":
      return `nmap -sn ${host}`;
    case "ns":
      return `dig NS ${host} +short`;
    case "ownership":
      return `whois ${target} | grep -iE 'netrange|orgname|asn'`;
    case "ports":
      return `nmap -sS -Pn -T4 --top-ports 1000 ${target}`;
    case "services":
      return `nmap -sV -sC -Pn -T4 -p- ${target}`;
    case "reverse":
      return `dig -x ${target} +short`;
    case "http":
      return `nmap -sV -Pn -p 443 --script "http-headers,http-title" ${target}`;
    default:
      return `nmap -sV -Pn ${target}`;
  }
}
