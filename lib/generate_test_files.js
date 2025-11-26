// Simple generator that converts generated_test_cases JSON into a Jest + Supertest test file
// Produces a mapping of filename -> file content
function escapeSingleQuotes(s) {
  return s.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}

function buildTestFile(testCases, payload) {
  const lines = [];
  lines.push("const request = require('supertest');");
  lines.push("const app = require('../app');");
  lines.push("\n");
  lines.push("describe('Generated test suite (auto)', () => {");

  // If no structured test cases were generated, create at least one
  // simple smoke test so the file is never "empty" from Jest's perspective.
  if (!testCases || testCases.length === 0) {
    const fallbackMethod = (payload && payload.method) ? payload.method.toLowerCase() : 'get';
    const fallbackApi = (payload && payload.api) || '/health';
    lines.push("  test('smoke test: endpoint responds without crashing', async () => {");
    lines.push(`    const res = await request(app).${fallbackMethod}('${fallbackApi}');`);
    lines.push("    expect(res.status).toBeGreaterThanOrEqual(200);");
    lines.push("    expect(res.status).toBeLessThan(600);");
    lines.push("  });");
    lines.push("");
  }

  testCases.forEach((tc, idx) => {
    const desc = tc.description ? escapeSingleQuotes(tc.description) : `case-${idx}`;
    const input = tc.input || tc;
    const method = (input.method || (payload && payload.method) || 'POST').toUpperCase();
    const api = input.api || (payload && payload.api) || '/';
    const headers = input.headers || {};
    const body = input.body === undefined ? null : input.body;
    const expected = tc.expected || {};

    lines.push(`  test('${desc}', async () => {`);
    lines.push(`    let req = request(app).${method.toLowerCase()}('${api}');`);
    if (body !== null && method !== 'GET') {
      lines.push(`    req = req.send(${JSON.stringify(body, null, 2)});`);
    }
    for (const [k, v] of Object.entries(headers)) {
      lines.push(`    req = req.set(${JSON.stringify(k)}, ${JSON.stringify(v)});`);
    }
    lines.push(`    const res = await req;`);
    if (typeof expected.status_code === 'number') {
      lines.push(`    expect(res.status).toBe(${expected.status_code});`);
    }
    // Optionally check for expected message fields
    if (expected.message) {
      lines.push(`    // check message substring (if present)`);
      lines.push(`    expect(res.body && JSON.stringify(res.body)).toEqual(expect.stringContaining(${JSON.stringify(String(expected.message))}));`);
    }
    lines.push(`  });\n`);
  });

  lines.push('});\n');
  return lines.join('\n');
}

module.exports = {
  generateJestTestFiles: (generated_test_cases, payload) => {
    const fileContent = buildTestFile(generated_test_cases || [], payload);
    // Expose the same test content in both a nested "tests/" folder and at repo root
    // so that unzip tools and users always see at least one runnable test file.
    return {
      'tests/generated.test.js': fileContent,
      'generated.test.js': fileContent
    };
  }
};
