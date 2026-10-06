// Transparent scoring. Shown to visitors on every report ("How the score works").
// Start at 100. Each failed check subtracts its weight; a warning subtracts about half.
// Info, "couldn't test", and passed checks subtract nothing.
// Any high-severity failure caps the score at 69 (a D at best): one exposed .env file or a
// broken certificate matters more than a page full of perfect headers.
export const WEIGHTS = { high: 15, medium: 8, low: 3 };
export const WARN_WEIGHTS = { high: 8, medium: 4, low: 1 };
export const HIGH_CAP = 69;
export const GRADES = [[90, "A"], [80, "B"], [70, "C"], [60, "D"], [0, "F"]];

export const gradeFor = (score) => GRADES.find(([min]) => score >= min)[1];

export function scoreFindings(findings) {
  const deductions = [];
  for (const f of findings) {
    const table = f.status === "fail" ? WEIGHTS : f.status === "warn" ? WARN_WEIGHTS : null;
    const pts = table ? table[f.severity] || 0 : 0;
    if (pts) deductions.push({ id: f.id, status: f.status, severity: f.severity, points: pts });
  }
  const raw = Math.max(0, 100 - deductions.reduce((a, d) => a + d.points, 0));
  const highFail = findings.some((f) => f.status === "fail" && f.severity === "high");
  const score = highFail ? Math.min(raw, HIGH_CAP) : raw;
  const counts = { high: 0, medium: 0, low: 0, pass: 0, info: 0 };
  for (const f of findings) {
    if (f.status === "fail" || f.status === "warn") counts[f.severity] = (counts[f.severity] || 0) + 1;
    else if (f.status === "pass") counts.pass++;
    else counts.info++;
  }
  return { score, grade: gradeFor(score), raw, capped: highFail && raw > HIGH_CAP, deductions, counts };
}

export const SCORING_RULES = {
  start: 100, fail: WEIGHTS, warn: WARN_WEIGHTS, highCap: HIGH_CAP,
  grades: GRADES.map(([min, g]) => ({ grade: g, min })),
};
