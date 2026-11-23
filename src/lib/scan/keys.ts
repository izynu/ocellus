/**
 * Keys the visitor supplies for sources that cannot be queried without one.
 *
 * Several of the best sources are key-gated: VirusTotal, Shodan, Censys and
 * urlscan. A static page cannot ship a key of its own, and it should not want
 * to, so the honest options were to list them as unusable or to let the visitor
 * bring their own. This is the second option.
 *
 * Three rules make that safe and keep the product's promise intact:
 *
 *  1. A key lives in this browser's `localStorage` and nowhere else. It is sent
 *     only to the service it belongs to, in that service's own header, exactly
 *     as the service documents. Nothing is proxied through this site, and no
 *     key is ever written into a report, an export or a URL.
 *  2. A check that needs a key reports `unavailable` with the reason "no key
 *     stored" when there is none. It never silently skips, because a silent
 *     skip reads as a pass.
 *  3. Removing a key removes it from storage immediately. There is no shadow
 *     copy.
 */

export type KeyedProvider = "virustotal" | "shodan" | "censys" | "urlscan";

export const KEY_STORAGE_PREFIX = "ocellus.key.";

export type KeyedProviderMeta = {
  id: KeyedProvider;
  name: string;
  /** Where a visitor gets a key. */
  url: string;
  /** What the key unlocks, in one line. */
  unlocks: string;
  /** The header the service expects. Shown to the visitor so it is not a secret. */
  header: string;
  /** One line on the free tier, so nobody is surprised by a quota. */
  tier: string;
};

export const KEYED_PROVIDERS: KeyedProviderMeta[] = [
  {
    id: "virustotal",
    name: "VirusTotal",
    url: "https://www.virustotal.com/gui/my-apikey",
    unlocks: "A URL and domain checked against 90 or more engines, with the detections named.",
    header: "x-apikey",
    tier: "Free: 4 requests a minute, 500 a day.",
  },
  {
    id: "shodan",
    name: "Shodan",
    url: "https://account.shodan.io/",
    unlocks: "Full host record for the address: banners, products, versions and open ports.",
    header: "key query parameter",
    tier: "Free: a limited query credit and a slower rate.",
  },
  {
    id: "censys",
    name: "Censys",
    url: "https://search.censys.io/account/api",
    unlocks: "A second internet-wide index, useful when an address is invisible to Shodan.",
    header: "Authorization: Basic",
    tier: "Free: a monthly credit allowance.",
  },
  {
    id: "urlscan",
    name: "urlscan.io",
    url: "https://urlscan.io/user/profile/",
    unlocks: "Submit a fresh scan and read the rendered page, its requests and its verdict.",
    header: "api-key",
    tier: "Free: a daily submission quota.",
  },
];

/** A censys key is an id and a secret, stored as the joined pair. */
export type KeyValue = string;

function storage(): Storage | null {
  try {
    // A private window with storage blocked still scans; it just cannot keep a key.
    const probe = "__ocellus_probe__";
    localStorage.setItem(probe, "1");
    localStorage.removeItem(probe);
    return localStorage;
  } catch {
    return null;
  }
}

export function readKey(provider: KeyedProvider): KeyValue | null {
  const store = storage();
  if (!store) return null;
  try {
    const value = store.getItem(KEY_STORAGE_PREFIX + provider);
    return value && value.trim() ? value.trim() : null;
  } catch {
    return null;
  }
}

export function writeKey(provider: KeyedProvider, value: string): boolean {
  const store = storage();
  if (!store) return false;
  try {
    const trimmed = value.trim();
    if (trimmed) store.setItem(KEY_STORAGE_PREFIX + provider, trimmed);
    else store.removeItem(KEY_STORAGE_PREFIX + provider);
    return true;
  } catch {
    return false;
  }
}

export function clearKey(provider: KeyedProvider): void {
  const store = storage();
  if (!store) return;
  try {
    store.removeItem(KEY_STORAGE_PREFIX + provider);
  } catch {
    // Nothing to do.
  }
}

/** True when the browser can persist a key at all. */
export function storageAvailable(): boolean {
  return storage() !== null;
}

/** The header a provider wants, built from the stored key. For a real request. */
export function authHeaders(provider: KeyedProvider, key: string): Record<string, string> {
  switch (provider) {
    case "virustotal":
      return { "x-apikey": key };
    case "censys":
      // Censys v2 uses HTTP basic with id:secret, and the pair is what is stored.
      return { Authorization: "Basic " + btoa(key) };
    case "urlscan":
      return { "API-Key": key };
    case "shodan":
    default:
      // Shodan takes the key as a query parameter; no header.
      return {};
  }
}

/** Whether a stored value looks like a key for this provider, before use. */
export function looksLikeKey(provider: KeyedProvider, key: string): boolean {
  const v = key.trim();
  if (!v) return false;
  if (provider === "censys") return /^[^:\s]+:[^:\s]+$/.test(v);
  if (provider === "virustotal") return v.length >= 32;
  return v.length >= 12;
}
