/**
 * Interface friction and manipulative design, decided from the static DOM.
 *
 * The predecessor of this check invented its findings with a seeded random
 * number generator, which made every result unusable as evidence. This version
 * only reports what a parsed document can prove: an attribute that is present,
 * a string that is written in the markup, a control that exists. Anything that
 * depends on rendering, styling or a multi-step flow is listed in
 * `notAssessable` instead of being guessed at.
 *
 * Every rule below names the authority it is judged against. For consent, the
 * standard is legal rather than stylistic: a pre-ticked box is not consent
 * under GDPR Article 7, and the FTC's 2022 staff report on dark patterns
 * describes the rest of these as deceptive or unfair design.
 */

import type { CheckDefinition, CheckResult, Finding, Severity } from "../types";

export type DarkPatternData = {
  detected: Array<{ rule: string; count: number; samples: string[] }>;
  checkedBoxes: number;
  forms: number;
  dialogs: number;
  scarcityPhrases: string[];
  notAssessable: string[];
};

type RuleId =
  | "prechecked-consent"
  | "prechecked-paid-addon"
  | "confirmshaming"
  | "asymmetric-dismissal"
  | "scarcity-pressure"
  | "forced-consent"
  | "hidden-unsubscribe"
  | "sneak-into-basket";

type RuleMeta = {
  title: string;
  severity: Severity;
  remediation: string;
  reference: { label: string; url: string };
  detail: (count: number) => string;
};

/** Labels that mark a checkbox as a marketing or data-sharing opt-in. */
const CONSENT_LABEL =
  /newsletter|offers|updates|marketing|partner|third.?part|sms|text message|call|share|contact me/i;

/** Labels that mark a checkbox as a paid extra. */
const PAID_LABEL = /[$€£]|\/\s?mo\b|per month|\d+\s*(usd|eur|gbp)/i;

/** Labels that mark a checkbox as an add-on bundled into a purchase. */
const ADDON_LABEL = /insurance|protection|warranty|add.?on|upgrade|donat/i;

/** Decline copy written to make refusal feel like a loss. */
const CONFIRMSHAMING =
  /no thanks,? i (prefer|like|want|don'?t)|i don'?t want|i'?ll pass|maybe later,? i|no,? i'?m (fine|okay)|i prefer to (stay|lose|miss)/i;

/** Urgency and scarcity phrasing. Presence is not proof of a false claim. */
const SCARCITY =
  /\b(only \d+ (left|remaining)|hurry|ends (today|soon)|last chance|\d+ (people|others) (are|is) (viewing|looking)|limited (time|stock)|expires in)\b/gi;

/** Copy that names a subscription exit. */
const UNSUBSCRIBE =
  /unsubscribe|cancel (my )?(subscription|plan|account)|manage (subscription|plan)/i;

/**
 * A dismiss control drawn as a single glyph rather than a word. The glyphs are
 * compared here as literal characters and never copied into a finding string.
 */
const BARE_GLYPH = /^[×✕✖xX]$/;

const GDPR_ART_7 = {
  label: "GDPR Article 7: Conditions for consent",
  url: "https://gdpr-info.eu/art-7-gdpr/",
};
const FTC_DARK_PATTERNS = {
  label: "FTC: Bringing Dark Patterns to Light",
  url: "https://www.ftc.gov/reports/bringing-dark-patterns-light",
};
const WCAG_NAME_ROLE_VALUE = {
  label: "WCAG 4.1.2: Name, Role, Value",
  url: "https://www.w3.org/WAI/WCAG22/Understanding/name-role-value.html",
};

const RULES: Record<RuleId, RuleMeta> = {
  "prechecked-consent": {
    title: "Pre-ticked marketing consent",
    severity: "high",
    remediation:
      "Leave every marketing and data-sharing checkbox unchecked by default. Consent must follow from a clear affirmative action, so a box the visitor never touched cannot be consent.",
    reference: GDPR_ART_7,
    detail: (count) =>
      `${count} checkbox${count === 1 ? "" : "es"} for marketing or data sharing carr${count === 1 ? "ies" : "y"} the checked attribute, so the visitor is opted in without acting. Pre-ticked consent boxes do not meet the standard for consent under GDPR Article 7.`,
  },
  "prechecked-paid-addon": {
    title: "Pre-checked paid extra",
    severity: "high",
    remediation:
      "Never pre-check a paid add-on. Require an explicit opt-in and show the price next to the control at the moment of selection.",
    reference: FTC_DARK_PATTERNS,
    detail: (count) =>
      `${count} checked checkbox${count === 1 ? "" : "es"} mention${count === 1 ? "s" : ""} a price, which means a charge is selected before the visitor chooses it.`,
  },
  confirmshaming: {
    title: "Confirmshaming in a decline option",
    severity: "medium",
    remediation:
      "Use neutral copy on both options, for example \"Subscribe\" and \"Not now\". The decline path should not carry a value judgment.",
    reference: FTC_DARK_PATTERNS,
    detail: (count) =>
      `${count} link or button${count === 1 ? "" : "s"} phrase the refusal as a personal loss or a self-deprecating choice rather than a neutral action.`,
  },
  "asymmetric-dismissal": {
    title: "Dismiss control with no accessible name",
    severity: "low",
    remediation:
      "Give the close control a text label or aria-label, a target of at least 24 by 24 CSS pixels, and the same prominence as the primary action. WCAG 2.5.8 sets the minimum target size.",
    reference: WCAG_NAME_ROLE_VALUE,
    detail: (count) =>
      `${count} dialog${count === 1 ? "" : "s"} carr${count === 1 ? "ies" : "y"} a dismiss control with no accessible name: either its only content is a glyph, or its size is set small in an inline style or class. A screen reader announces it as an unnamed button.`,
  },
  "scarcity-pressure": {
    title: "Scarcity or urgency wording",
    severity: "low",
    remediation:
      "Keep urgency claims only where they are true and can be substantiated, such as a real stock count or a real deadline. A claim that cannot be evidenced is a deceptive practice under the FTC Act.",
    reference: FTC_DARK_PATTERNS,
    detail: (count) =>
      `${count} urgency or scarcity phrase${count === 1 ? "" : "s"} appear in the visible text. These claims can be legitimate, so the finding is that the pattern is present; the site should be able to substantiate each one.`,
  },
  "forced-consent": {
    title: "Marketing consent required to continue",
    severity: "high",
    remediation:
      "Make marketing consent optional and separate from the action the visitor came to perform. Consent that is a condition of service is not freely given under GDPR Article 7(4).",
    reference: GDPR_ART_7,
    detail: (count) =>
      `${count} form${count === 1 ? "" : "s"} require${count === 1 ? "s" : ""} a marketing checkbox before the submit button will accept the form. Bundling consent with the primary action removes the visitor's free choice.`,
  },
  "hidden-unsubscribe": {
    title: "Unsubscribe or cancel link hidden from view",
    severity: "high",
    remediation:
      "Expose the cancellation route at the same level as the signup route. Do not hide it with the hidden attribute, aria-hidden, display:none or visibility:hidden.",
    reference: FTC_DARK_PATTERNS,
    detail: (count) =>
      `${count} link${count === 1 ? "" : "s"} to unsubscribe, cancel or manage a subscription sit${count === 1 ? "s" : ""} inside an element marked hidden, aria-hidden or hidden by an inline style.`,
  },
  "sneak-into-basket": {
    title: "Add-on pre-selected in a form",
    severity: "high",
    remediation:
      "Leave add-ons unchecked by default and state the price beside each one. Selecting an extra must be the visitor's action, not the default.",
    reference: FTC_DARK_PATTERNS,
    detail: (count) =>
      `${count} checked checkbox${count === 1 ? "" : "es"} in a form mention${count === 1 ? "s" : ""} insurance, protection, a warranty, an upgrade or a donation, which adds a paid item the visitor did not choose.`,
  },
};

/** Resolve the text a visitor would read beside a checkbox. */
function labelTextFor(doc: Document, input: Element): string {
  const id = input.getAttribute("id");
  if (id) {
    try {
      const explicit = doc.querySelector(`label[for="${CSS.escape(id)}"]`);
      const text = explicit?.textContent?.trim();
      if (text) return text;
    } catch {
      // An id that is not a valid selector is skipped rather than fatal.
    }
  }
  const wrapped = input.closest("label");
  const wrappedText = wrapped?.textContent?.trim();
  if (wrappedText) return wrappedText;

  const labelledBy = input.getAttribute("aria-labelledby");
  if (labelledBy) {
    const parts = labelledBy
      .split(/\s+/)
      .map((ref) => {
        try {
          return doc.getElementById(ref)?.textContent?.trim() ?? "";
        } catch {
          return "";
        }
      })
      .filter(Boolean);
    if (parts.length > 0) return parts.join(" ");
  }
  const aria = input.getAttribute("aria-label")?.trim();
  if (aria) return aria;

  // A checkbox and its text are often siblings with no label element. Read the
  // next sibling so the common pattern is not silently missed.
  const next = input.nextElementSibling?.textContent?.trim();
  if (next) return next;

  // The parent is the last resort, and only when it reads like a single label.
  // A large parent would pull in page copy and make the label rules fire on
  // unrelated words.
  const parentText = input.parentElement?.textContent?.replace(/\s+/g, " ").trim() ?? "";
  return parentText.length <= 200 ? parentText : "";
}

/** A short CSS-like path from an ancestor to the element, for evidence. */
function selectorPath(el: Element, max = 100): string {
  const parts: string[] = [];
  let current: Element | null = el;
  while (current && current.tagName.toLowerCase() !== "html" && parts.length < 6) {
    let part = current.tagName.toLowerCase();
    const id = current.getAttribute("id");
    if (id) {
      part += `#${id.slice(0, 30)}`;
    } else {
      const firstClass = (current.getAttribute("class") ?? "").trim().split(/\s+/).filter(Boolean)[0];
      if (firstClass) part += `.${firstClass.slice(0, 24)}`;
    }
    parts.unshift(part);
    current = current.parentElement;
  }
  const path = parts.join(" > ");
  return path.length > max ? "..." + path.slice(path.length - max + 3) : path;
}

function clip(text: string, max = 120): string {
  const flat = text.replace(/\s+/g, " ").trim();
  return flat.length > max ? flat.slice(0, max - 3) + "..." : flat;
}

function isChecked(input: Element): boolean {
  return input.hasAttribute("checked") || input.getAttribute("aria-checked") === "true";
}

/** Text content of the document with non-visible nodes removed. */
function visibleText(doc: Document): string {
  const body = doc.body;
  if (!body) return "";
  const clone = body.cloneNode(true) as HTMLElement;
  // Script and style bodies are not read by a visitor, and neither is markup
  // that is hidden by an attribute or an inline style. Excluding both keeps a
  // hidden "limited time" string in a template from counting as visible copy.
  for (const node of Array.from(
    clone.querySelectorAll(
      'script,style,noscript,template,[hidden],[aria-hidden="true"],[style*="display:none" i],[style*="visibility:hidden" i]'
    )
  )) {
    node.remove();
  }
  return (clone.textContent ?? "").replace(/\s+/g, " ").trim();
}

/** True when the element or an ancestor is hidden by an attribute or inline style. */
function isHidden(el: Element): boolean {
  let current: Element | null = el;
  while (current && current.tagName.toLowerCase() !== "html") {
    if (current.hasAttribute("hidden")) return true;
    if (current.getAttribute("aria-hidden") === "true") return true;
    const style = (current.getAttribute("style") ?? "").replace(/\s+/g, "").toLowerCase();
    if (style.includes("display:none") || style.includes("visibility:hidden")) return true;
    current = current.parentElement;
  }
  return false;
}

/** Interactive controls inside a dialog, used to judge whether an exit exists. */
function controlsIn(el: Element): Element[] {
  return Array.from(el.querySelectorAll("button, a[href], input[type=submit], input[type=button]"));
}

export const darkPatterns: CheckDefinition = {
  id: "dark-patterns",
  title: "Interface friction",
  question: "Does the page use pre-ticked consent, guilt-based refusal copy, hidden exits or urgency pressure?",
  group: "ux",
  weight: 2,
  async run(ctx): Promise<CheckResult> {
    const started = performance.now();
    const page = await ctx.html();
    const doc = page.doc;

    if (!doc) {
      return {
        id: this.id,
        title: this.title,
        question: this.question,
        status: "unavailable",
        headline: "The document could not be retrieved, so interface patterns could not be read.",
        findings: [],
        ms: Math.round(performance.now() - started),
        source: page.via,
        note: "Without a parsed document there is nothing to inspect. The document reader returned no HTML, which happens when a site blocks automated fetching entirely.",
      };
    }

    const hits: Array<{ rule: RuleId; sample: string; selector: string }> = [];
    const addHit = (rule: RuleId, sample: string, selector: string) => {
      hits.push({ rule, sample: clip(sample), selector });
    };

    const forms = Array.from(doc.querySelectorAll("form"));
    const checkboxes = Array.from(doc.querySelectorAll('input[type="checkbox"]'));
    const checkedBoxes = checkboxes.filter(isChecked);

    // --- rules 1, 2, 8: pre-checked boxes ---
    // A checkbox outside a form is not part of a submission, so the rules that
    // concern a submitted choice are scoped to forms.
    for (const box of checkedBoxes) {
      const form = box.closest("form");
      if (!form) continue;
      const label = labelTextFor(doc, box);
      const selector = selectorPath(box);
      if (CONSENT_LABEL.test(label)) addHit("prechecked-consent", label, selector);
      if (PAID_LABEL.test(label)) addHit("prechecked-paid-addon", label, selector);
      if (ADDON_LABEL.test(label)) addHit("sneak-into-basket", label, selector);
    }

    // --- rule 3: confirmshaming ---
    const declineControls = Array.from(
      doc.querySelectorAll("a, button, [role=button], input[type=submit], input[type=button]")
    );
    for (const control of declineControls) {
      const text =
        control.tagName.toLowerCase() === "input"
          ? control.getAttribute("value") ?? ""
          : control.textContent ?? "";
      const trimmed = text.replace(/\s+/g, " ").trim();
      if (trimmed && CONFIRMSHAMING.test(trimmed)) {
        addHit("confirmshaming", trimmed, selectorPath(control));
      }
    }

    // --- rule 4: asymmetric dismissal ---
    // Only markup that identifies itself as a dialog is considered. A fixed
    // positioned element with no role is included because that is how most
    // newsletter popups are written.
    const dialogCandidates = Array.from(
      doc.querySelectorAll(
        '[role="dialog"], [role="alertdialog"], dialog, [class*="modal" i], [class*="popup" i]'
      )
    );
    // A fixed-position element with no dialog role is how most newsletter
    // popups are written, so it is inspected for a close control too. It is not
    // eligible for the one-control rule, which would otherwise fire on every
    // fixed header that happens to hold a single button.
    const fixedOverlays: Element[] = [];
    for (const el of Array.from(doc.querySelectorAll("[style]"))) {
      if (
        /position\s*:\s*fixed/i.test(el.getAttribute("style") ?? "") &&
        !dialogCandidates.includes(el) &&
        // A fixed element nested inside a dialog is part of that dialog and
        // would otherwise be inspected twice.
        !dialogCandidates.some((candidate) => candidate.contains(el))
      ) {
        fixedOverlays.push(el);
      }
    }

    for (const dialog of [...dialogCandidates, ...fixedOverlays]) {
      const closeControls = Array.from(
        dialog.querySelectorAll(
          'button[aria-label], [class*="close" i], [class*="dismiss" i], button, a[href], span'
        )
      ).filter((el) => {
        const aria = el.getAttribute("aria-label") ?? "";
        const cls = el.getAttribute("class") ?? "";
        const glyph = (el.textContent ?? "").trim();
        return /close|dismiss/i.test(aria) || /close|dismiss/i.test(cls) || BARE_GLYPH.test(glyph);
      });

      let flagged = false;
      for (const close of closeControls) {
        const glyph = (close.textContent ?? "").trim();
        // An empty aria-label is not an accessible name, so presence alone is
        // not enough. Each attribute must carry text.
        const hasName = ["aria-label", "aria-labelledby", "title"].some(
          (attr) => (close.getAttribute(attr) ?? "").trim().length > 0
        );
        const style = (close.getAttribute("style") ?? "").replace(/\s+/g, "").toLowerCase();
        const fontSize = /font-size:(\d+(?:\.\d+)?)px/.exec(style);
        const tinyByStyle = fontSize ? Number(fontSize[1]) <= 12 : false;
        const tinyByClass = /(^|[-_])(xs|tiny|mini|small)([-_]|$)/i.test(close.getAttribute("class") ?? "");

        if (BARE_GLYPH.test(glyph) && !hasName) {
          addHit("asymmetric-dismissal", `${selectorPath(close)} (bare glyph, no accessible name)`, selectorPath(dialog));
          flagged = true;
          break;
        }
        if ((tinyByStyle || tinyByClass) && !hasName) {
          addHit("asymmetric-dismissal", `${selectorPath(close)} (small dismiss control, no accessible name)`, selectorPath(dialog));
          flagged = true;
          break;
        }
      }

      // A dialog with a single control and no close affordance leaves the
      // visitor one action only. This is read from markup alone, so a dialog
      // that is dismissed by clicking the backdrop is not detected.
      if (!flagged && dialogCandidates.includes(dialog)) {
        const controls = controlsIn(dialog);
        if (controls.length === 1 && closeControls.length === 0) {
          addHit(
            "asymmetric-dismissal",
            `${selectorPath(dialog)} (one control, no close affordance)`,
            selectorPath(dialog)
          );
        }
      }
    }

    // --- rule 5: scarcity and urgency copy ---
    const text = visibleText(doc);
    const scarcityPhrases: string[] = [];
    for (const match of text.matchAll(SCARCITY)) {
      const phrase = match[0].replace(/\s+/g, " ").trim();
      if (phrase && !scarcityPhrases.some((p) => p.toLowerCase() === phrase.toLowerCase())) {
        scarcityPhrases.push(phrase);
        if (scarcityPhrases.length >= 10) break;
      }
    }
    for (const phrase of scarcityPhrases) {
      addHit("scarcity-pressure", phrase, "visible text");
    }

    // --- rule 6: forced consent ---
    for (const form of forms) {
      const submits = Array.from(
        form.querySelectorAll('button[type="submit"], button:not([type]), input[type="submit"]')
      );
      const submitText = submits
        .map((s) =>
          s.tagName.toLowerCase() === "input"
            ? s.getAttribute("value") ?? ""
            : s.textContent ?? ""
        )
        .join(" ");
      if (!/continue/i.test(submitText)) continue;

      const requiredConsent = Array.from(form.querySelectorAll('input[type="checkbox"]')).filter(
        (box) =>
          (box.hasAttribute("required") || box.getAttribute("aria-required") === "true") &&
          CONSENT_LABEL.test(labelTextFor(doc, box))
      );
      if (requiredConsent.length > 0) {
        addHit(
          "forced-consent",
          `${clip(submitText)} with required consent: ${clip(labelTextFor(doc, requiredConsent[0]), 60)}`,
          selectorPath(form)
        );
      }
    }

    // --- rule 7: hidden unsubscribe ---
    for (const link of Array.from(doc.querySelectorAll("a[href]"))) {
      const linkText = (link.textContent ?? "").replace(/\s+/g, " ").trim();
      if (!linkText || !UNSUBSCRIBE.test(linkText)) continue;
      if (isHidden(link)) {
        addHit("hidden-unsubscribe", linkText, selectorPath(link));
      }
    }

    // --- assemble one finding per rule ---
    const byRule = new Map<RuleId, Array<{ sample: string; selector: string }>>();
    for (const hit of hits) {
      const list = byRule.get(hit.rule) ?? [];
      list.push({ sample: hit.sample, selector: hit.selector });
      byRule.set(hit.rule, list);
    }

    const findings: Finding[] = [];
    const detected: DarkPatternData["detected"] = [];
    for (const [rule, list] of byRule) {
      const meta = RULES[rule];
      detected.push({
        rule,
        count: list.length,
        samples: list.slice(0, 5).map((h) => h.sample),
      });
      findings.push({
        id: `dark-${rule}`,
        title: meta.title,
        detail: meta.detail(list.length),
        severity: meta.severity,
        remediation: meta.remediation,
        reference: meta.reference,
        evidence: list.slice(0, 8).map((h) => ({
          label: h.selector,
          value: h.sample,
          tone: "bad" as const,
        })),
      });
    }

    // Worst first so the report reader sees the legal problem before the copy
    // problem. Severity order matches the scoring layer.
    const rank: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    findings.sort((a, b) => rank[a.severity] - rank[b.severity]);

    const notAssessable = [
      "Contrast ratios and visual prominence need computed styles from a rendered page.",
      "How many clicks a cancellation flow takes cannot be counted from one document.",
      "Whether the price changes at checkout cannot be seen from this page alone.",
      "Whether a free trial auto-charges needs the billing flow, which is not executed here.",
      "Whether a countdown timer is real or resets on reload needs the running page.",
    ];

    const serious = findings.filter((f) => f.severity === "high" || f.severity === "critical");
    const status: CheckResult["status"] =
      serious.length > 0 ? "fail" : findings.length > 0 ? "warn" : "pass";

    const headline =
      findings.length === 0
        ? `No pre-ticked consent, guilt-based refusal copy, hidden exits or urgency claims were found across ${forms.length} form${forms.length === 1 ? "" : "s"} and ${checkedBoxes.length} checked box${checkedBoxes.length === 1 ? "" : "es"}.`
        : `${findings.length} interface pattern${findings.length === 1 ? "" : "s"} detected across ${forms.length} form${forms.length === 1 ? "" : "s"}, ${checkedBoxes.length} checked box${checkedBoxes.length === 1 ? "" : "es"} and ${dialogCandidates.length} dialog${dialogCandidates.length === 1 ? "" : "s"}.`;

    const note = [
      "This reads the static markup only. Contrast ratios, the visual prominence of one control over another, the number of clicks a cancellation flow takes, price changes at checkout and trial auto-charging are not detectable here and are not claimed.",
      "Hiding applied by an external stylesheet cannot be seen, so a link hidden only by a class rule is not reported.",
    ];
    if (page.suspectInterstitial) {
      note.push("The fetched document looked like a consent wall or bot check, so the patterns may belong to that gate rather than the page.");
    }

    return {
      id: this.id,
      title: this.title,
      question: this.question,
      status,
      headline,
      findings,
      data: {
        detected,
        checkedBoxes: checkedBoxes.length,
        forms: forms.length,
        dialogs: dialogCandidates.length,
        scarcityPhrases,
        notAssessable,
      } satisfies DarkPatternData,
      ms: Math.round(performance.now() - started),
      source: page.via,
      note: note.join(" "),
    };
  },
};
