import test from "node:test";
import { SNIPPET, cleanWorst } from "../api/_lib/explain.js";
import assert from "node:assert/strict";
import { scoreFindings, gradeFor, WEIGHTS, WARN_WEIGHTS, HIGH_CAP } from "../api/_lib/score.js";
import { CATALOG, fallbackText } from "../api/_lib/catalog.js";

const f = (id, status, severity) => ({ id, status, severity });

test("perfect run scores 100 / A; info and errors never cost points", () => {
  const s = scoreFindings([f("a", "pass", "high"), f("b", "info", "low"), f("c", "error", "medium")]);
  assert.equal(s.score, 100); assert.equal(s.grade, "A"); assert.deepEqual(s.deductions, []);
});

test("deductions follow the published weights", () => {
  const s = scoreFindings([f("a", "fail", "medium"), f("b", "fail", "low"), f("c", "warn", "medium"), f("d", "warn", "low")]);
  assert.equal(s.score, 100 - WEIGHTS.medium - WEIGHTS.low - WARN_WEIGHTS.medium - WARN_WEIGHTS.low);
  assert.equal(s.deductions.length, 4);
  assert.deepEqual(s.counts, { high: 0, medium: 2, low: 2, pass: 0, info: 0 });
});

test("a high-severity failure caps the score", () => {
  const s = scoreFindings([f("x", "fail", "high")]);
  assert.equal(s.raw, 85); assert.equal(s.score, HIGH_CAP); assert.equal(s.capped, true); assert.equal(s.grade, "D");
  assert.equal(scoreFindings([f("x", "warn", "high")]).score, 92, "a high warning doesn't trigger the cap");
});

test("score floors at 0", () => {
  assert.equal(scoreFindings(Array.from({ length: 20 }, (_, i) => f("x" + i, "fail", "high"))).score, 0);
});

test("grade boundaries", () => {
  assert.deepEqual([100, 90, 89, 80, 79, 70, 69, 60, 59, 0].map(gradeFor), ["A", "A", "B", "B", "C", "C", "D", "D", "F", "F"]);
});

test("every check has a title, category, and hand-written copy for every status it can produce", () => {
  const statuses = { pass: true, fail: true, warn: true, info: true };
  for (const [id, c] of Object.entries(CATALOG)) {
    assert.ok(c.title && c.cat && c.fixBy, id);
    for (const st of Object.keys(statuses)) {
      const t = fallbackText({ id, status: st });
      assert.ok(t.what.length > 10, `${id}/${st} what`);
      if ((st === "fail" || st === "warn") && c.fixBy !== "none") {
        assert.ok(t.fix.length > 10, `${id}/${st} fix`);
        assert.match(t.fix, /^Fixed /, `${id}/${st} fix is a short "How it's fixed" line`);
        assert.ok(!SNIPPET.test(t.fix), `${id}/${st} fix has no snippet: ${t.fix}`);
        assert.ok(t.worst.length > 20, `${id}/${st} worst`);
        assert.equal(cleanWorst(t.worst), t.worst, `${id}/${st} worst passes the same filters as AI text`);
      }
      if (st === "pass" || st === "info") assert.equal(t.worst, "", `${id}/${st} has no worst case`);
      assert.ok(!SNIPPET.test(t.what), `${id}/${st} what has no snippet: ${t.what}`);
    }
  }
});

test("honesty guardrail: referred-out checks never claim Nick fixes them; copy never calls a site secure", () => {
  assert.equal(CATALOG.exposed_files.fixBy, "refer");
  assert.match(fallbackText({ id: "exposed_files", status: "fail" }).fix, /developer, host, or a security professional.*urgently/i);
  assert.match(fallbackText({ id: "exposed_files", status: "fail" }).fix, /refer/i);
  const all = JSON.stringify(CATALOG);
  assert.doesNotMatch(all, /penetration|pentest|is secure\b|fully secure|guarantee/i);
});
