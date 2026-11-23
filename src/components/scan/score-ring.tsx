/**
 * The score, drawn as one ring.
 *
 * A ring rather than a bar because the score is a proportion of a whole and a
 * ring states that without a label. The arc is drawn with a dash offset, so it
 * animates from empty to its value on mount and needs no library. The number in
 * the middle is the real value from the first paint; only the arc moves, so a
 * reader never waits on an animation to learn the score.
 */

import { useEffect, useRef, useState } from "react";

const SIZE = 132;
const STROKE = 9;
const RADIUS = (SIZE - STROKE) / 2;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

export function ScoreRing({
  score,
  grade,
  tone,
}: {
  score: number;
  grade: string;
  /** A tone class: tone-pass, tone-warn or tone-fail. */
  tone: string;
}) {
  const [drawn, setDrawn] = useState(false);
  const mounted = useRef(false);

  // The first frame renders the arc empty, then one state change starts the
  // transition. Doing it this way keeps the server-rendered markup and the
  // first client render identical, which a CSS animation on an inline value
  // would not.
  useEffect(() => {
    if (mounted.current) return;
    mounted.current = true;
    const frame = requestAnimationFrame(() => setDrawn(true));
    return () => cancelAnimationFrame(frame);
  }, []);

  const clamped = Math.max(0, Math.min(100, score));
  const filled = (clamped / 100) * CIRCUMFERENCE;

  return (
    <div className="relative flex-none" style={{ width: SIZE, height: SIZE }}>
      <svg
        width={SIZE}
        height={SIZE}
        viewBox={`0 0 ${SIZE} ${SIZE}`}
        role="img"
        aria-label={`Score ${score} out of 100, grade ${grade}`}
        style={{ transform: "rotate(-90deg)" }}
      >
        <circle
          cx={SIZE / 2}
          cy={SIZE / 2}
          r={RADIUS}
          fill="none"
          strokeWidth={STROKE}
          className="ring__track"
        />
        <circle
          cx={SIZE / 2}
          cy={SIZE / 2}
          r={RADIUS}
          fill="none"
          strokeWidth={STROKE}
          strokeDasharray={CIRCUMFERENCE}
          strokeDashoffset={drawn ? CIRCUMFERENCE - filled : CIRCUMFERENCE}
          className={`ring__value ${tone}`}
          style={{
            stroke: "currentColor",
            transition: "stroke-dashoffset 900ms cubic-bezier(0.22, 0.61, 0.36, 1)",
          }}
        />
      </svg>
      <div
        className="absolute inset-0 flex flex-col items-center justify-center"
        style={{ pointerEvents: "none" }}
      >
        {/*
         * 36px is the size for a three-digit score on a 132px ring: any
         * larger and "100" starts to crowd the stroke, any smaller and the
         * number stops being the first thing a reader sees. Tabular figures
         * keep 100 from shifting sideways beside 87.
         */}
        <span
          className={`tabular ${tone}`}
          style={{ fontSize: 36, fontWeight: 620, lineHeight: 1, letterSpacing: "-0.02em" }}
        >
          {clamped}
        </span>
        <span
          style={{
            marginTop: 5,
            fontSize: 11.5,
            fontWeight: 560,
            letterSpacing: "0.06em",
            textTransform: "uppercase",
            color: "var(--muted-foreground)",
          }}
        >
          Grade {grade}
        </span>
      </div>
    </div>
  );
}
