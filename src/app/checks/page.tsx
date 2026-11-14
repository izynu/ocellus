import { SiteShell } from "@/components/site/site-shell";
import { checks, GROUP_LABEL, GROUP_ORDER, groupOf } from "@/lib/checks";
import { SITE, asset } from "@/lib/site";

/**
 * The check catalogue.
 *
 * Generated from the registry so it cannot fall out of step with what the scan
 * runs. Each entry is the check's own title, question and weight; nothing here
 * is written by hand except the framing around it.
 */

export const metadata = {
  title: "Checks",
  description: `Every check Ocellus runs: ${checks.length} checks in ${GROUP_ORDER.length} groups, with the question each one asks and the weight it carries in the score.`,
  alternates: { canonical: asset("/checks") },
};

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
            and the grade bands are on the <a href={asset("/method")}>method page</a>.
          </p>
        </div>
      </header>

      {GROUP_ORDER.map((group) => {
        const members = groupOf(group);
        if (members.length === 0) return null;
        const headingId = `group-${group}`;
        return (
          <section key={group} className="mt-12 md:mt-16" aria-labelledby={headingId}>
            <div className="flex flex-wrap items-baseline justify-between gap-3">
              <h2 id={headingId} style={{ fontSize: 22 }}>
                {GROUP_LABEL[group]}
              </h2>
              <p
                className="tabular"
                style={{ fontSize: 13, color: "var(--muted-foreground)" }}
              >
                {members.length} {members.length === 1 ? "check" : "checks"}
              </p>
            </div>
            <hr className="hairline mt-3 mb-0" />

            <dl className="m-0">
              {members.map((check, index) => (
                <div
                  key={check.id}
                  className="grid grid-cols-1 gap-1.5 py-5 md:grid-cols-[minmax(0,1fr)_auto] md:gap-6"
                  style={{
                    borderTop: index === 0 ? "none" : "1px solid var(--border)",
                  }}
                >
                  <div>
                    <dt className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
                      <span style={{ fontSize: 16, fontWeight: 600 }}>{check.title}</span>
                      <span className="mono" style={{ color: "var(--muted-foreground)" }}>
                        {check.id}
                      </span>
                    </dt>
                    <dd
                      className="m-0 mt-1.5"
                      style={{
                        fontSize: 14.5,
                        lineHeight: 1.55,
                        maxWidth: "68ch",
                        color: "var(--muted-foreground)",
                      }}
                    >
                      {check.question}
                    </dd>
                  </div>
                  <div className="md:pt-0.5">
                    <span className="chip tabular" title={`Weight ${check.weight}: ${WEIGHT_MEANING[check.weight]}`}>
                      weight {check.weight}
                    </span>
                  </div>
                </div>
              ))}
            </dl>
          </section>
        );
      })}

      <section className="mt-16 md:mt-20" aria-labelledby="weights">
        <h2 id="weights" style={{ fontSize: 22 }}>
          Weight in one table
        </h2>
        <div className="prose mt-4">
          <table>
            <thead>
              <tr>
                <th scope="col">Weight</th>
                <th scope="col">Meaning</th>
                <th scope="col">Checks</th>
              </tr>
            </thead>
            <tbody>
              {([3, 2, 1] as const).map((weight) => {
                const members = checks.filter((c) => c.weight === weight);
                return (
                  <tr key={weight}>
                    <td className="tabular">{weight}</td>
                    <td>{WEIGHT_MEANING[weight]}</td>
                    <td className="tabular">{members.length}</td>
                  </tr>
                );
              })}
              <tr>
                <td className="tabular">{checks.length}</td>
                <td>Total checks in the registry</td>
                <td className="tabular">{checks.length}</td>
              </tr>
            </tbody>
          </table>
          <p>
            The count in the last row is the size of the registry in {SITE.name}. It is
            printed from the array itself, so it cannot disagree with the scan.
          </p>
        </div>
      </section>
      </div>
    </SiteShell>
  );
}
