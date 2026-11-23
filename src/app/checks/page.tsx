import { SiteShell } from "@/components/site/site-shell";
import { CheckCatalogue, type CheckCatalogueGroup } from "@/components/scan/check-catalogue";
import { checks, GROUP_LABEL, GROUP_ORDER, groupOf } from "@/lib/checks";
import { asset, pageMeta } from "@/lib/site";

/**
 * The check catalogue.
 *
 * Generated from the registry so it cannot fall out of step with what the scan
 * runs. Each entry is the check's own title, question and weight; nothing here
 * is written by hand except the framing around it.
 *
 * The registry entries carry `run` functions, which cannot be serialised into a
 * client bundle, so this page projects each one to its four display fields
 * before handing the list to the client filter. The grouping matches the report:
 * one section per group, in `GROUP_ORDER`, with the group's own area hue.
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

const CATALOGUE_GROUPS: CheckCatalogueGroup[] = GROUP_ORDER.map((group) => ({
  group,
  label: GROUP_LABEL[group],
  members: groupOf(group).map((check) => ({
    id: check.id,
    title: check.title,
    question: check.question,
    weight: check.weight,
  })),
}));

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
              informs the report but a problem in it is not, on its own, a structural weakness.
              <strong> 2</strong> is material: the check describes a control that changes the
              site&apos;s exposure in a real way. <strong>3</strong> is structural: the check
              covers a property that other protections depend on.
            </p>
            <p>
              The score is the weighted mean of each check&apos;s status fraction over the checks
              that returned a verdict. A check that reports <strong>unavailable</strong> or{" "}
              <strong>skipped</strong> leaves the denominator: it neither raises nor lowers the
              score, because a source that did not answer is not evidence either way. The exact
              fractions, the treatment of unavailable results and the grade bands are on the{" "}
              <a href={asset("/method")}>method page</a>. The findings themselves are grouped by
              area in every report, so a certificate problem and a cookie problem never appear in
              the same list.
            </p>
          </div>
        </header>

        <CheckCatalogue groups={CATALOGUE_GROUPS} />

        <section className="mt-16 md:mt-20" aria-labelledby="weights">
          <h2 id="weights" style={{ fontSize: 22 }}>
            Weight in one place
          </h2>
          <p
            className="mt-3"
            style={{ fontSize: 14.5, color: "var(--muted-foreground)", maxWidth: "62ch" }}
          >
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
                  <p className="box__body">
                    {WEIGHT_MEANING[weight]} weight. {" "}
                    {weight === 1
                      ? "Counts toward the score but never moves it far on its own."
                      : weight === 2
                        ? "Describes a control that changes the site's exposure in a real way."
                        : "Covers a property other protections depend on."}
                  </p>
                </li>
              );
            })}
          </ul>
        </section>
      </div>
    </SiteShell>
  );
}
