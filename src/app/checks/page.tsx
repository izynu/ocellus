import { SiteShell } from "@/components/site/site-shell";
import { checks, GROUP_LABEL, GROUP_ORDER, groupOf } from "@/lib/checks";
import { asset, pageMeta } from "@/lib/site";

/**
 * The check catalogue.
 *
 * Generated from the registry so it cannot fall out of step with what the scan
 * runs. Each entry is the check's own title, question and weight; nothing here
 * is written by hand except the framing around it.
 */

export const metadata = pageMeta({
  title: "Checks",
  description: `Every check Ocellus runs: ${checks.length} checks in ${GROUP_ORDER.length} groups, with the question each one asks and the weight it carries in the score.`,
  path: "/checks",
});

const WEIGHT_MEANING: Record<1 | 2 | 3, string> = {
  1: "context",
  2: "material",
  3: "structural",
};

export default function ChecksPage() {
  return (
    <SiteShell>
      <div className="container-page">
      <header className="rise pt-14 pb-2 md:pt-20">
        <p className="eyebrow">Catalogue</p>
        <h1 className="mt-4" style={{ fontSize: "clamp(1.9rem, 4.4vw, 2.7rem)" }}>
          Every check, the question it asks, and what it weighs.
        </h1>
        <div className="prose mt-6">
          <p>
            A scan runs {checks.length} checks across {GROUP_ORDER.length} groups. Each check
            owns exactly one question about the target and answers it with a status, a headline
            and whatever evidence the source returned.
          </p>
          <p>
            A check&apos;s <strong>weight</strong> is how much it contributes to the overall
            score. It takes one of three values. <strong>1</strong> is context: the check
            informs the report but a problem in it is not, on its own, a structural weakness.{" "}
            <strong>2</strong> is material: the check describes a control that changes the
            site&apos;s exposure in a real way. <strong>3</strong> is structural: the check
            covers a property that other protections depend on.
          </p>
          <p>
            The score is the weighted mean of each check&apos;s status fraction over the checks
            that returned a verdict. The exact fractions, the treatment of unavailable results
            and the grade bands are on the <a href={asset("/method")}>method page</a>. The
            findings themselves are grouped by area in every report, so a certificate problem
            and a cookie problem never appear in the same list.
          </p>
        </div>
      </header>

      {GROUP_ORDER.map((group, groupIndex) => {
        const members = groupOf(group);
        if (members.length === 0) return null;
        const headingId = `group-${group}`;
        return (
          <section
            key={group}
            className={`mt-12 md:mt-16 area-${group}`}
            aria-labelledby={headingId}
          >
            <div className="flex flex-wrap items-baseline justify-between gap-3">
              <div className="area-head">
                <span className="dot" aria-hidden="true" />
                <h2 id={headingId} style={{ fontSize: 22 }}>
                  {GROUP_LABEL[group]}
                </h2>
              </div>
              <p
                className="tabular"
                style={{ fontSize: 13, color: "var(--muted-foreground)" }}
              >
                {members.length} {members.length === 1 ? "check" : "checks"}
              </p>
            </div>

            <ul className="box-grid mt-4">
              {members.map((check, index) => (
                <li
                  key={check.id}
                  className="box box--area rise"
                  style={{ ["--i" as string]: Math.min(index + groupIndex, 8) }}
                >
                  <div className="box__head">
                    <span className="dot" aria-hidden="true" />
                    <h3 className="box__title">{check.title}</h3>
                  </div>
                  <p className="box__body">{check.question}</p>
                  <div className="box__meta">
                    <span
                      className="chip tabular"
                      title={`Weight ${check.weight}: ${WEIGHT_MEANING[check.weight]}`}
                    >
                      weight {check.weight}
                    </span>
                    <span className="mono">{check.id}</span>
                  </div>
                </li>
              ))}
            </ul>
          </section>
        );
      })}

      <section className="mt-16 md:mt-20" aria-labelledby="weights">
        <h2 id="weights" style={{ fontSize: 22 }}>
          Weight in one place
        </h2>
        <p className="mt-3" style={{ fontSize: 14.5, color: "var(--muted-foreground)", maxWidth: "62ch" }}>
          Every check in the registry falls into one of three weights. The counts are printed
          from the registry itself, so they cannot disagree with the scan.
        </p>
        <ul className="box-grid mt-5">
          {([3, 2, 1] as const).map((weight, index) => {
            const members = checks.filter((c) => c.weight === weight);
            return (
              <li key={weight} className="box rise" style={{ ["--i" as string]: index }}>
                <div className="flex items-baseline justify-between gap-3">
                  <span className="stat" style={{ fontSize: 24 }}>
                    {weight}
                  </span>
                  <span className="chip tabular">{members.length} checks</span>
                </div>
                <p className="box__body">{WEIGHT_MEANING[weight]}</p>
              </li>
            );
          })}
        </ul>
      </section>
      </div>
    </SiteShell>
  );
}
