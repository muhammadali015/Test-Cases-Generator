const fs = require('fs');
const path = require('path');
const filePath = path.join(__dirname, '..', 'LTM', 'memory.json');
const content = {
  example_signature_0001: {
    result: {
      status_message: 'Generated 8 test cases for POST /login',
      generated_test_cases: [
        {
          description: 'Valid input returns success response',
          input: { api: '/login', method: 'POST', body: { email: 'user@example.com', password: 'Str0ngP@ss!' } },
          expected: { status_code: 201, message: 'Request processed successfully' }
        }
      ],
      test_files: ['tests/generated.test.js'],
      ltm_hit: false
    },
    timestamp: new Date().toISOString()
  },
  __meta: {
    agent: 'testcase_generator_agent',
    created: new Date().toISOString(),
    notes: 'LTM stores recent test-case generation results. Legacy generator artifacts removed.'
  }
};

fs.mkdirSync(path.dirname(filePath), { recursive: true });
fs.writeFileSync(filePath, JSON.stringify(content, null, 2), 'utf8');
console.log('WROTE', filePath);