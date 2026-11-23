/**
 * The background scene.
 *
 * Three soft light pools and a fine grid behind everything. It is the surface
 * the glass chrome refracts, and it carries no information: no logo, no
 * illustration, nothing that could be mistaken for content. `aria-hidden` and
 * `pointer-events: none` so it never appears in the accessibility tree.
 */

export function Scene() {
  return (
    <div className="scene" aria-hidden="true">
      <div className="scene__pool scene__pool--a" />
      <div className="scene__pool scene__pool--b" />
      <div className="scene__pool scene__pool--c" />
    </div>
  );
}
