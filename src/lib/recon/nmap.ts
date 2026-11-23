/**
 * The nmap command catalogue.
 *
 * A browser cannot run nmap. There is no raw socket, no SYN packet, no ARP
 * probe; the page is forbidden from opening the connection a port scan needs.
 * Pretending otherwise would be the one thing this project does not do, so this
 * catalogue does the honest version of the job: it writes the exact command for
 * the target you are looking at, explains what each one answers, and hands it to
 * you to run on a machine you control.
 *
 * Every command here is a command an owner auditing their own host would run.
 * The set follows the sequence nmapAutomator and the standard workflow use:
 * discovery, then service and version, then default scripts, then a full port
 * sweep, then focused checks. Each entry names the nmap flags it uses so the
 * command is readable rather than a wall of switches.
 *
 * The API key source is HackerTarget's nmap endpoint, which relays an nmap scan
 * for an address. As of 23 November 2026 that endpoint answers "error valid key
 * required" without one, so it is offered only when the visitor has stored a
 * HackerTarget key, and the check that uses it says so.
 */

export type NmapProfile = {
  /** Stable id for the React key. */
  id: string;
  /** What this scan answers, imperative. */
  title: string;
  /** One sentence on when to choose it. */
  when: string;
  /** The command, with `{host}` and `{ip}` placeholders. */
  command: string;
  /** The nmap flags, spelled out. */
  flags: string;
  /** Rough duration, so nobody starts a UDP sweep expecting seconds. */
  time: string;
  /** True when the scan is loud and needs authorisation to be unambiguous. */
  loud: boolean;
};

export const NMAP_PROFILES: NmapProfile[] = [
  {
    id: "discovery",
    title: "Host discovery, no ports",
    when: "Is it up at all, before spending a scan on ports.",
    command: "nmap -sn {host}",
    flags: "-sn: ping scan only, no port scan",
    time: "seconds",
    loud: false,
  },
  {
    id: "top-ports",
    title: "The 1000 most common ports",
    when: "The default first pass on any host.",
    command: "nmap -sS -Pn -T4 --top-ports 1000 {ip}",
    flags: "-sS SYN scan, -Pn skip host discovery, -T4 faster timing",
    time: "under a minute",
    loud: false,
  },
  {
    id: "service-version",
    title: "Service and version detection",
    when: "Which software is behind each open port, and at what version.",
    command: "nmap -sV -Pn -T4 -p- {ip}",
    flags: "-sV version probes, -p- every port",
    time: "10 to 40 minutes across all 65535 ports",
    loud: true,
  },
  {
    id: "default-scripts",
    title: "Default scripts and versions",
    when: "What the safe script set can tell you about banners and headers.",
    command: "nmap -sC -sV -Pn -T4 {ip}",
    flags: "-sC default script set, -sV version probes",
    time: "2 to 10 minutes",
    loud: true,
  },
  {
    id: "full-tcp",
    title: "Every TCP port",
    when: "A service on an unusual port is exactly what a top-1000 scan misses.",
    command: "nmap -sS -Pn -T4 -p- --min-rate 1000 {ip}",
    flags: "-p- all 65535 ports, --min-rate 1000 at least 1000 packets a second",
    time: "5 to 20 minutes",
    loud: true,
  },
  {
    id: "udp-top",
    title: "The 200 most common UDP ports",
    when: "DNS, SNMP, NTP, TFTP and other services that only speak UDP.",
    command: "nmap -sU -Pn --top-ports 200 --max-retries 1 {ip}",
    flags: "-sU UDP scan, --max-retries 1 keeps it finite",
    time: "10 to 30 minutes; UDP is slow by nature",
    loud: true,
  },
  {
    id: "http-title",
    title: "HTTP titles across open web ports",
    when: "What each web service calls itself, which names the app and its version.",
    command: 'nmap -sV -Pn -p 80,443,8080,8443,8000,8888 --script "http-title,http-headers" {ip}',
    flags: "--script http-title,http-headers",
    time: "under a minute",
    loud: false,
  },
  {
    id: "vuln-scan",
    title: "Vulnerability scripts",
    when: "After a full version scan, to check each CVE against the banner.",
    command: 'nmap -sV -Pn -p- --script "vuln" {ip}',
    flags: "--script vuln runs the vulnerability detection set",
    time: "20 minutes and up",
    loud: true,
  },
  {
    id: "firewall-evasion",
    title: "Fragmented SYN",
    when: "A firewall drops the plain SYN; this splits it instead.",
    command: "nmap -sS -Pn -f --mtu 8 -T2 {ip}",
    flags: "-f fragment packets, --mtu 8 fragment size, -T2 patient timing",
    time: "1 to 5 minutes",
    loud: true,
  },
  {
    id: "subnet",
    title: "A whole /24",
    when: "Sweeping the network a single host sits in.",
    command: "nmap -sn -T4 {subnet}",
    flags: "-sn discovery across the range",
    time: "under a minute",
    loud: false,
  },
];

/** Fill placeholders. A plain replace; the output is only ever shown as text. */
export function renderNmap(
  profile: NmapProfile,
  vars: { host: string; ip: string; subnet: string }
): string {
  return profile.command
    .replaceAll("{host}", vars.host)
    .replaceAll("{ip}", vars.ip)
    .replaceAll("{subnet}", vars.subnet);
}

/**
 * The nmapAutomator one-liner for a host, which chains the same sequence
 * automatically. It is the script the user asked to expose, and it is offered
 * as the convenience form of the profiles above.
 */
export function nmapAutomatorCommand(host: string, mode: "quick" | "basic" | "full" | "vulns"): string {
  return `./nmapAutomator.sh -H ${host} -t ${mode}`;
}

export const NMAP_AUTOMATOR_MODES: Array<{ mode: "quick" | "basic" | "full" | "vulns"; label: string; what: string }> = [
  { mode: "quick", label: "Quick", what: "Top ports and their versions. The first look at a new host." },
  { mode: "basic", label: "Basic", what: "All TCP ports, service versions and the default scripts." },
  { mode: "full", label: "Full", what: "The basic pass plus UDP on the common set; the slowest complete view." },
  { mode: "vulns", label: "Vulns", what: "Version detection followed by the vulnerability script set." },
];
