/*
  =============================================================
  == TEST CASE GENERATOR AGENT (SMART GIT LTM + ROBUST)
  =============================================================
  1. Supervisor Compliant
  2. LTM with Content Hashing (Files/Zip)
  3. LTM with Commit SHA Hashing (Git)
  4. Rate Limiting (10 RPM)
  5. Robust handling for JSON test-case formats
*/

const express = require('express');
const fetch = require('node-fetch');
const { simpleGit } = require('simple-git');
const { glob } = require('glob');
const fs = require('fs').promises;
const path = require('path');
const os = require('os');
const AdmZip = require('adm-zip');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;
const { generateJestTestFiles } = require('./lib/generate_test_files');

const GEMINI_API_KEY = process.env.GEMINI_API_KEY || "";
app.use(cors());
app.use(express.json({ limit: '50mb' }));

// --- TEST FRAMEWORK / COVERAGE HELPERS (GLOBAL) ---
function inferTestFramework(language) {
  const lang = (language || 'javascript').toString().toLowerCase();
  if (['js', 'javascript', 'node', 'ts', 'typescript'].includes(lang)) return 'jest+supertest';
  if (['python', 'py'].includes(lang)) return 'pytest';
  if (['java'].includes(lang)) return 'junit5';
  if (['php'].includes(lang)) return 'phpunit';
  if (['c#', 'csharp', 'cs'].includes(lang)) return 'nunit';
  if (['go', 'golang'].includes(lang)) return 'testing';
  if (['c', 'cpp', 'c++'].includes(lang)) return 'gtest';
  return 'jest+supertest';
}

function buildCoverageAnalysis(normalizedPayload, testCases) {
  const fieldNames = (normalizedPayload.fields || []).map(f => (typeof f === 'string' ? f : (f && f.name) || 'field'));
  const coveredScenarios = [];

  if (testCases.some(tc => /Valid input/i.test(tc.description || ''))) {
    coveredScenarios.push('happy_path');
  }
  if (testCases.some(tc => /Missing .* triggers validation error/i.test(tc.description || ''))) {
    coveredScenarios.push('missing_required_fields');
  }
  if (testCases.some(tc => /Invalid data type/i.test(tc.description || ''))) {
    coveredScenarios.push('invalid_types');
  }
  if (testCases.some(tc => /Method Not Allowed/i.test(JSON.stringify(tc.expected || {})))) {
    coveredScenarios.push('http_method_mismatch');
  }
  if (testCases.some(tc => /Empty request body/i.test(tc.description || ''))) {
    coveredScenarios.push('empty_body');
  }
  if (testCases.some(tc => /Unauthorized access/i.test(JSON.stringify(tc.expected || {})))) {
    coveredScenarios.push('auth_missing');
  }

  const missing = [];
  if (!coveredScenarios.includes('happy_path')) missing.push('happy_path');
  if (!coveredScenarios.includes('missing_required_fields') && fieldNames.length > 0) missing.push('missing_required_fields');
  if (!coveredScenarios.includes('invalid_types') && fieldNames.length > 0) missing.push('invalid_types');
  if (!coveredScenarios.includes('http_method_mismatch')) missing.push('http_method_mismatch');
  if (!coveredScenarios.includes('empty_body')) missing.push('empty_body');

  return JSON.stringify({
    api: normalizedPayload.api,
    method: normalizedPayload.method,
    total_generated_tests: testCases.length,
    fields: fieldNames,
    covered_scenarios: coveredScenarios,
    missing_scenarios: missing,
    notes: "Coverage is inferred from generated scenarios only; no static analysis of controller code is performed."
  });
}

function buildRecommendations(normalizedPayload, testCases, framework) {
  const recs = [];
  recs.push(`Use the generated ${framework} suite as a starting point and refine assertions to match your actual response schema for ${normalizedPayload.method} ${normalizedPayload.api}.`);
  recs.push('Add integration tests that hit the real database or stubbed repositories to cover persistence and query behavior.');
  recs.push('Introduce tests for failure modes of external services (e.g., timeouts, 5xx responses) if your handler calls upstream APIs.');
  if (normalizedPayload.requires_auth) {
    recs.push('Add tests for different auth roles/permissions (valid token with insufficient scope, expired token, malformed token).');
  }
  recs.push('Consider splitting the generated suite into route-specific files (e.g., tests/auth/login.test.js) as your project grows.');

  return recs.join(' ');
}

// ---  LONG-TERM MEMORY (LTM) SETUP  ---
const LTM_FILE_PATH = path.join(__dirname, 'LTM', 'memory.json');
const LTM_DIR = path.dirname(LTM_FILE_PATH);
const LTM_WINDOW_SIZE = 10;

async function readLTM() {
  try {
    await fs.mkdir(LTM_DIR, { recursive: true });
    const data = await fs.readFile(LTM_FILE_PATH, 'utf-8');
    return JSON.parse(data);
  } catch (error) {
    if (error.code === 'ENOENT') return {};
    return {};
  }
}

async function writeLTM(data) {
  try {
    await fs.mkdir(LTM_DIR, { recursive: true });
    await fs.writeFile(LTM_FILE_PATH, JSON.stringify(data, null, 2));
  } catch (error) {
    console.error("[LTM] Write failed:", error.message);
  }
}

// ---  SMART GIT HASHING  ---
async function getGitCommitHash(repoUrl) {
    try {
        console.log(`[Git LTM] Fetching HEAD commit hash for ${repoUrl}...`);
        const result = await simpleGit().listRemote([repoUrl, 'HEAD']);
        if (!result) return null;
        const hash = result.split('\t')[0]; 
        console.log(`[Git LTM] Detected Commit SHA: ${hash}`);
        return hash;
    } catch (error) {
        console.warn(`[Git LTM] Failed to get remote hash: ${error.message}. Fallback to URL.`);
        return null;
    }
}

async function generateTaskSignature(taskData) {
  const hash = crypto.createHash('sha256');

  hash.update(taskData.language || 'unknown');
  hash.update(JSON.stringify(taskData.search_patterns || 'default'));

  // Include payload (endpoint, method, fields) in signature so different endpoints get different cache entries
  if (taskData.payload) {
    hash.update(JSON.stringify({
      api: taskData.payload.api || '/',
      method: taskData.payload.method || 'POST',
      fields: taskData.payload.fields || []
    }));
  }

  if (taskData.zip_file_base64) {
      hash.update('mode:zip');
      hash.update(taskData.zip_file_base64); 
  } else if (taskData.code_files_base64 && taskData.code_files_base64.length > 0) {
      hash.update('mode:files');
      const sortedFiles = [...taskData.code_files_base64].sort((a, b) => a.file_path.localeCompare(b.file_path));
      for (const file of sortedFiles) {
          hash.update(file.file_path);
          hash.update(file.content_base64);
      }
  } else if (taskData.git_repo_url) {
      hash.update('mode:git');
      hash.update(taskData.git_repo_url);
      const commitHash = await getGitCommitHash(taskData.git_repo_url);
      if (commitHash) {
          hash.update(commitHash);
      } else {
          hash.update('HEAD'); 
      }
  }

  if (taskData.existing_test_manifest) {
    hash.update(JSON.stringify(taskData.existing_test_manifest));
  }

  return hash.digest('hex');
}

function findInLTM(signature, ltmData) {
  const entry = ltmData[signature];
  return (entry && entry.result && entry.timestamp) ? entry.result : null;
}

async function saveToLTM(signature, result, ltmData) {
  console.log(`[LTM] Saving result. Sig: ${signature.substring(0, 10)}...`);
  ltmData[signature] = { result, timestamp: new Date().toISOString() };
  
  const entries = Object.entries(ltmData);
  if (entries.length > LTM_WINDOW_SIZE) {
    entries.sort((a, b) => new Date(a[1].timestamp) - new Date(b[1].timestamp));
    const keysToDelete = entries.slice(0, entries.length - LTM_WINDOW_SIZE).map(e => e[0]);
    for (const k of keysToDelete) delete ltmData[k];
  }
  await writeLTM(ltmData);
}


// Simple root route so hitting http://localhost:PORT in a browser
// shows a friendly message instead of "Cannot GET /".
app.get('/', (req, res) => {
  res
    .status(200)
    .json({
      status: "ok",
      message: "Testcase Generator Agent is running. Use POST /execute or GET /health."
    });
});

app.get('/health', (req, res) => {
  res.status(200).json({ status: "I'm up", agent_name: "Testcase Generator Agent (Smart LTM)" });
});

app.post('/execute', async (req, res) => {
  const incomingMessage = req.body;
  if (incomingMessage.type !== 'task_assignment') return res.status(400).json({ message: "Invalid type" });

  const taskData = incomingMessage["results/task"] || {};
  console.log(`Received task ${incomingMessage.message_id}`);
  
  let ltmData;
  let taskSignature;

  try {
    // --- SMART LTM CHECK ---
    // For now, skip LTM cache to ensure fresh generation (can re-enable later)
    // ltmData = await readLTM();
    // taskSignature = await generateTaskSignature(taskData); 
    // console.log(`[LTM] Signature: ${taskSignature}`);
    // const cachedResult = findInLTM(taskSignature, ltmData);
    // if (cachedResult) {
    //   console.log("[LTM HIT] Returning cached response.");
    //   return res.status(200).json(createSuccessResponseFromCache(incomingMessage.message_id, cachedResult));
    // }
    
    let ltmData = {};
    let taskSignature = '';
    console.log("[LTM] Cache disabled for debugging - always generating fresh");

    console.log("[LTM MISS] Processing fresh...");
    console.log(`[DEBUG] Task data keys: ${Object.keys(taskData).join(', ')}`);
    console.log(`[DEBUG] Payload received: ${JSON.stringify(taskData.payload || {}, null, 2)}`);
    
    // --- EXECUTION FLOW ---
    const { task_type, payload = {} } = taskData;
    console.log(`[DEBUG] Extracted payload: api=${payload.api}, method=${payload.method}, fields=${JSON.stringify(payload.fields)}`);

    if (task_type !== 'generate_test_cases') {
      return res
        .status(400)
        .json(createErrorResponse(
          incomingMessage.message_id,
          "Unsupported task type",
          `Received task_type=${task_type}, but this agent only handles generate_test_cases.`
        ));
    }

    // Auto-detect endpoint from project files if "auto" is requested OR if using default endpoint
    let finalPayload = payload;
    const isDefaultEndpoint = !payload.api || payload.api === '/generated-endpoint' || payload.api === '/';
    const shouldAutoDetect = payload.metadata?.auto_detect || payload.api === 'auto' || isDefaultEndpoint;
    
    if (shouldAutoDetect) {
      console.log('[Auto-detect] Attempting to extract endpoints from project files...');
      const detectedEndpoint = await autoDetectEndpointFromFiles(taskData);
      if (detectedEndpoint) {
        console.log(`[Auto-detect] Found endpoint: ${detectedEndpoint.api} ${detectedEndpoint.method} with fields: ${detectedEndpoint.fields.join(', ')}`);
        finalPayload = { ...payload, ...detectedEndpoint };
      } else {
        console.warn('[Auto-detect] Could not auto-detect endpoint, using provided/default values');
        console.warn(`[Auto-detect] Using payload: api=${payload.api}, method=${payload.method}, fields=${JSON.stringify(payload.fields)}`);
      }
    } else {
      console.log(`[Payload] Using provided endpoint: ${payload.api} ${payload.method} with fields: ${JSON.stringify(payload.fields)}`);
    }

    const normalizedPayload = normalizeTestCasePayload(finalPayload);
    console.log(`[DEBUG] Normalized payload: api=${normalizedPayload.api}, method=${normalizedPayload.method}, fields=${JSON.stringify(normalizedPayload.fields)}, requires_auth=${normalizedPayload.requires_auth}`);
    
    const generated_test_cases = await generateTestCasesWithGemini(taskData, normalizedPayload);
    console.log(`[DEBUG] Generated ${generated_test_cases.length} test cases`);
    const targetLanguage = taskData.language || payload.language || 'javascript';

    const statusMessage = `Generated ${generated_test_cases.length} test cases for ${normalizedPayload.method.toUpperCase()} ${normalizedPayload.api}`;

    const successResponse = createSuccessResponse(
      incomingMessage.message_id,
      statusMessage,
      generated_test_cases,
      normalizedPayload,
      targetLanguage
    );
      // Generate runnable Jest test files (basic) and attach as ZIP (base64) to response
      try {
        const testFilesMap = generateJestTestFiles(generated_test_cases, normalizedPayload);
        const zip = new AdmZip();
        for (const [filePath, content] of Object.entries(testFilesMap)) {
          zip.addFile(filePath, Buffer.from(content, 'utf8'));
        }
        const zipBuffer = zip.toBuffer();
        const zipBase64 = zipBuffer.toString('base64');
        successResponse["results/task"].test_suite_zip_base64 = zipBase64;
        successResponse["results/task"].test_files = Object.keys(testFilesMap);
      } catch (e) {
        console.warn('[TestGen] Failed to generate test files:', e && e.message);
      }
    
    // Temporarily disabled LTM save for debugging
    // await saveToLTM(taskSignature, successResponse["results/task"], ltmData);
    console.log(`[DEBUG] Final response: ${generated_test_cases.length} test cases for ${normalizedPayload.api}`);
    res.status(200).json(successResponse);

  } catch (error) {
    console.error("Fatal Error:", error);
    res.status(500).json(createErrorResponse(incomingMessage.message_id, "Internal Error", error.message));
  }
});

// --- HELPERS ---

function createSuccessResponse(relatedId, statusMessage, testCases, normalizedPayload, targetLanguage) {
  const framework = inferTestFramework(targetLanguage);

  return {
    message_id: `test-agent-${uuidv4()}`,
    sender: "testcase_generator_agent",
    recipient: "supervisor",
    type: "task_response",
    related_message_id: relatedId,
    status: "completed",
    "results/task": {
      status_message: statusMessage,
      generated_test_cases: testCases,
      test_cases: {
        framework,
        target_language: targetLanguage,
        api: normalizedPayload.api,
        method: normalizedPayload.method,
        scenarios_count: testCases.length
      },
      coverage_analysis: buildCoverageAnalysis(normalizedPayload, testCases),
      recommendations: buildRecommendations(normalizedPayload, testCases, framework),
      ltm_hit: false
    },
    timestamp: new Date().toISOString()
  };
}

function createSuccessResponseFromCache(relatedId, cachedTaskResult) {
  const safeResult = cachedTaskResult && typeof cachedTaskResult === 'object'
    ? cachedTaskResult
    : { status_message: "Cached result unavailable", generated_test_cases: [] };

  return {
    message_id: `test-agent-${uuidv4()}`,
    sender: "testcase_generator_agent",
    recipient: "supervisor",
    type: "task_response",
    related_message_id: relatedId,
    status: "completed",
    "results/task": {
      ...safeResult,
      status_message: `[LTM HIT] ${safeResult.status_message || "Cached response"}`,
      ltm_hit: true
    },
    timestamp: new Date().toISOString()
  };
}


function createErrorResponse(relatedId, message, error) {
  return {
    message_id: `test-agent-${uuidv4()}`,
    sender: "testcase_generator_agent",
    recipient: "supervisor",
    type: "task_response",
    related_message_id: relatedId,
    status: "failed",
    "results/task": { status_message: message, error_details: error },
    timestamp: new Date().toISOString()
  };
}

async function saveBase64File(base64String, extension) {
  const tempDir = os.tmpdir();
  const tempFilePath = path.join(tempDir, `${uuidv4()}.${extension}`);
  await fs.writeFile(tempFilePath, Buffer.from(base64String, 'base64'));
  return tempFilePath;
}

async function detectLanguage(language, filesToProcess) {
  if (language && language.trim() !== "") return language;
  if (!filesToProcess || filesToProcess.length === 0) return 'javascript';
  const ext = path.extname(filesToProcess[0].file_path).toLowerCase();
  const map = {".js": "javascript",".ts": "typescript",".py": "python",".java": "java",".kt": "kotlin",".scala": "scala",".swift": "swift",".go": "go",".rb": "ruby",".php": "php",".cs": "csharp",".cpp": "cpp",".c": "c",".rs": "rust"};
  if (map[ext]) return map[ext];

  const codeSnippet = filesToProcess[0].code_snippet;
  if (!GEMINI_API_KEY) throw new Error("GEMINI_API_KEY missing");
  const apiUrl = `http://localhost:3001`;
  const payload = { contents: [{ parts: [{ text: `Identify language:\n\n${codeSnippet.substring(0, 1000)}` }] }] };
  const apiResponse = await fetch(apiUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
  if (!apiResponse.ok) return 'javascript';
  const result = await apiResponse.json();
  return result.candidates?.[0]?.content?.parts?.[0]?.text.trim().toLowerCase() || 'javascript';
}

async function extractFilesFromZip(zipFilePath, searchPatterns) {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'zip-extract-'));
  try {
    const zip = new AdmZip(zipFilePath);
    zip.extractAllTo(tempDir, true);
    return await findCodeFiles(tempDir, searchPatterns); 
  } finally { await fs.rm(tempDir, { recursive: true, force: true }).catch(()=>{}); }
}

async function cloneRepoAndGetFiles(repoUrl, searchPatterns) {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'git-repo-'));
  try {
    await simpleGit().clone(repoUrl, tempDir, ['--depth=1']);
    return await findCodeFiles(tempDir, searchPatterns);
  } finally { await fs.rm(tempDir, { recursive: true, force: true }).catch(()=>{}); }
}

async function findCodeFiles(baseDir, searchPatterns) {
  const defaultFileTypes = ["*.js","*.ts","*.py","*.java","*.kt","*.scala","*.swift","*.go","*.rb","*.php","*.cs","*.cpp","*.c","*.rs"];
  const globPatterns = [];
  const patternsToUse = searchPatterns || ['**/'];
  for (const pattern of patternsToUse) {
    for (const type of defaultFileTypes) globPatterns.push(path.join(baseDir, pattern, type).replace(/\\/g, '/'));
  }
  const uniqueFiles = new Set();
  (await glob(globPatterns, { nodir: true, dot: false, ignore: '**/node_modules/**' })).forEach(f => uniqueFiles.add(f));
  const fileContents = [];
  for (const filePath of uniqueFiles) {
    try { fileContents.push({ file_path: path.relative(baseDir, filePath), code_snippet: await fs.readFile(filePath, 'utf-8') }); } catch (e) {}
  }
  
  // Prioritize route/controller/service files for better test generation
  const priorityKeywords = ['route', 'controller', 'service', 'api', 'handler', 'endpoint', 'app', 'index', 'main'];
  fileContents.sort((a, b) => {
    const aPath = a.file_path.toLowerCase();
    const bPath = b.file_path.toLowerCase();
    const aScore = priorityKeywords.reduce((score, kw) => score + (aPath.includes(kw) ? 10 : 0), 0);
    const bScore = priorityKeywords.reduce((score, kw) => score + (bPath.includes(kw) ? 10 : 0), 0);
    return bScore - aScore;
  });
  
  return fileContents;
}

// --- AUTO-DETECT ENDPOINTS FROM PROJECT FILES ---
async function autoDetectEndpointFromFiles(taskData) {
  let extractedFiles = [];

  // Collect files from all sources
  if (Array.isArray(taskData.code_files_base64) && taskData.code_files_base64.length > 0) {
    for (const file of taskData.code_files_base64) {
      try {
        const content = Buffer.from(file.content_base64, 'base64').toString('utf-8');
        extractedFiles.push({ file_path: file.file_path || 'file.js', code_snippet: content });
      } catch (e) {}
    }
  }

  if (extractedFiles.length === 0 && taskData.zip_file_base64) {
    try {
      const zipPath = await saveBase64File(taskData.zip_file_base64, 'zip');
      extractedFiles = await extractFilesFromZip(zipPath, taskData.search_patterns);
    } catch (e) {}
  }

  if (extractedFiles.length === 0 && taskData.git_repo_url) {
    try {
      extractedFiles = await cloneRepoAndGetFiles(taskData.git_repo_url, taskData.search_patterns);
    } catch (e) {}
  }

  console.log(`[Auto-detect] Analyzing ${extractedFiles.length} files for route definitions...`);
  
  // Analyze files to find route definitions
  for (const file of extractedFiles.slice(0, 20)) {
    const content = file.code_snippet || '';
    const filePath = file.file_path || '';
    
    if (!content || content.length < 50) continue; // Skip very short files

    // Express.js patterns: app.get('/path', ...), router.post('/path', ...), app.use('/path', ...)
    const expressPatterns = [
      /(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]/gi,
      /(?:app|router)\.use\s*\(\s*['"`]([^'"`]+)['"`]/gi
    ];

    // FastAPI patterns: @app.get("/path"), @router.post("/path")
    const fastApiPatterns = [
      /@(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]/gi
    ];

    // Flask patterns: @app.route('/path', methods=['POST'])
    const flaskPatterns = [
      /@(?:app|blueprint)\.route\s*\(\s*['"`]([^'"`]+)['"`][^)]*methods\s*=\s*\[['"`]([^'"`]+)['"`]/gi
    ];

    // Try Express patterns
    for (const pattern of expressPatterns) {
      const matches = [...content.matchAll(pattern)];
      if (matches.length > 0) {
        const match = matches[0];
        const method = match[1] ? match[1].toUpperCase() : 'GET';
        const path = match[2] || match[1];
        if (path && path.startsWith('/')) {
          // Try to extract fields from function body
          const funcBody = content.substring(content.indexOf(match[0]));
          const fieldMatches = funcBody.match(/(?:req\.body|req\.query|req\.params)\.(\w+)/g);
          const fields = fieldMatches ? [...new Set(fieldMatches.map(m => m.split('.')[1]))] : [];
          
          return {
            api: path,
            method: method,
            fields: fields.slice(0, 5), // Limit to 5 fields
            requires_auth: /(?:auth|jwt|token|bearer)/i.test(content)
          };
        }
      }
    }

    // Try FastAPI patterns
    for (const pattern of fastApiPatterns) {
      const matches = [...content.matchAll(pattern)];
      if (matches.length > 0) {
        const match = matches[0];
        const method = match[1].toUpperCase();
        const path = match[2];
        if (path && path.startsWith('/')) {
          // Try to extract fields from function parameters
          const funcDef = content.substring(content.indexOf(match[0]));
          const paramMatches = funcDef.match(/(\w+)\s*:\s*\w+/g);
          const fields = paramMatches ? paramMatches.map(m => m.split(':')[0].trim()) : [];
          
          return {
            api: path,
            method: method,
            fields: fields.slice(0, 5),
            requires_auth: /(?:Depends|Security|OAuth2)/i.test(content)
          };
        }
      }
    }

    // Try Flask patterns
    for (const pattern of flaskPatterns) {
      const matches = [...content.matchAll(pattern)];
      if (matches.length > 0) {
        const match = matches[0];
        const path = match[1];
        const method = match[2] ? match[2].toUpperCase() : 'GET';
        if (path && path.startsWith('/')) {
          const funcBody = content.substring(content.indexOf(match[0]));
          const fieldMatches = funcBody.match(/request\.(?:json|form|args)\[['"`](\w+)['"`]/g);
          const fields = fieldMatches ? [...new Set(fieldMatches.map(m => m.match(/['"`](\w+)['"`]/)[1]))] : [];
          
          return {
            api: path,
            method: method,
            fields: fields.slice(0, 5),
            requires_auth: /(?:@login_required|@require_auth)/i.test(content)
          };
        }
      }
    }
  }

  return null;
}

// --- GEMINI-POWERED TEST CASE GENERATION ---
async function generateTestCasesWithGemini(taskData, normalizedPayload) {
  // Fallback to rule-based generator if no API key configured
  if (!GEMINI_API_KEY) {
    console.warn('[Gemini] GEMINI_API_KEY missing, using rule-based test generator.');
    return buildTestCases(normalizedPayload);
  }

  // Collect comprehensive code context from ALL sources (combine files, ZIP, and git)
  const sampleFiles = [];
  let extractedFiles = [];

  // 1) Directly uploaded code files
  if (Array.isArray(taskData.code_files_base64) && taskData.code_files_base64.length > 0) {
    console.log(`[Gemini] Processing ${taskData.code_files_base64.length} uploaded code files...`);
    for (const file of taskData.code_files_base64) {
      try {
        const content = Buffer.from(file.content_base64, 'base64').toString('utf-8');
        extractedFiles.push({
          file_path: file.file_path || 'file.js',
          code_snippet: content
        });
      } catch (e) {
        console.warn(`[Gemini] Failed to decode file ${file.file_path}:`, e.message);
      }
    }
    console.log(`[Gemini] Added ${extractedFiles.length} files from direct upload`);
  }

  // 2) ZIP file of a project (COMBINE with existing files, don't skip)
  if (taskData.zip_file_base64) {
    try {
      console.log('[Gemini] Extracting files from ZIP...');
      const zipPath = await saveBase64File(taskData.zip_file_base64, 'zip');
      const filesFromZip = await extractFilesFromZip(zipPath, taskData.search_patterns);
      console.log(`[Gemini] Extracted ${filesFromZip.length} files from ZIP`);
      extractedFiles = extractedFiles.concat(filesFromZip);
      console.log(`[Gemini] Total files after ZIP: ${extractedFiles.length}`);
    } catch (e) {
      console.warn('[Gemini] Failed to extract ZIP context:', e && e.message);
    }
  }

  // 3) Git repo URL (COMBINE with existing files, don't skip)
  if (taskData.git_repo_url) {
    try {
      console.log(`[Gemini] Cloning repo ${taskData.git_repo_url}...`);
      const filesFromRepo = await cloneRepoAndGetFiles(taskData.git_repo_url, taskData.search_patterns);
      console.log(`[Gemini] Extracted ${filesFromRepo.length} files from repo`);
      extractedFiles = extractedFiles.concat(filesFromRepo);
      console.log(`[Gemini] Total files after git: ${extractedFiles.length}`);
    } catch (e) {
      console.warn('[Gemini] Failed to clone repo for context:', e && e.message);
    }
  }

  // Remove duplicates based on file_path
  const seenPaths = new Set();
  extractedFiles = extractedFiles.filter(f => {
    const path = f.file_path || '';
    if (seenPaths.has(path)) return false;
    seenPaths.add(path);
    return true;
  });
  console.log(`[Gemini] After deduplication: ${extractedFiles.length} unique files`);

  // Prepare sample files with more content (up to 20 files, 5000 chars each)
  const maxFiles = 20;
  const maxCharsPerFile = 5000;
  for (const f of extractedFiles.slice(0, maxFiles)) {
    sampleFiles.push({
      path: f.file_path,
      content_preview: (f.code_snippet || '').slice(0, maxCharsPerFile)
    });
  }

  const totalChars = sampleFiles.reduce((sum, f) => sum + (f.content_preview?.length || 0), 0);
  console.log(`[Gemini] Prepared ${sampleFiles.length} files for context (${totalChars} total chars)`);
  
  if (sampleFiles.length === 0) {
    console.warn('[Gemini] WARNING: No project files extracted! Test cases will be generic. Check that ZIP/git/files are being provided correctly.');
    console.warn(`[Gemini] Task data has: zip_file_base64=${!!taskData.zip_file_base64}, git_repo_url=${!!taskData.git_repo_url}, code_files_base64=${Array.isArray(taskData.code_files_base64) ? taskData.code_files_base64.length : 0}`);
  } else {
    console.log(`[Gemini] Sample file paths: ${sampleFiles.slice(0, 5).map(f => f.path).join(', ')}${sampleFiles.length > 5 ? '...' : ''}`);
    console.log(`[Gemini] First file preview (first 200 chars): ${sampleFiles[0]?.content_preview?.substring(0, 200)}`);
  }
  
  console.log(`[Gemini] About to call Gemini with endpoint: ${normalizedPayload.api}, method: ${normalizedPayload.method}, fields: ${JSON.stringify(normalizedPayload.fields)}`);

  const lang = taskData.language
    || normalizedPayload.metadata?.language
    || (sampleFiles[0] && sampleFiles[0].path && path.extname(sampleFiles[0].path).toLowerCase() === '.ts' ? 'typescript' : 'javascript');

  const prompt = [
    'You are an expert backend API test-case generator. Your task is to analyze the provided project code and generate COMPREHENSIVE test cases.',
    `Target implementation language: ${lang}.`,
    '',
    'INSTRUCTIONS:',
    '1. Analyze ALL provided source files (routes, controllers, services, models, middleware, etc.)',
    '2. Identify the actual endpoint implementation, validation logic, error handling, and business rules',
    '3. Generate 15-25 detailed test cases that cover:',
    '   - Happy path scenarios (2-3 tests with valid data variations)',
    '   - Required field validation (one test per required field missing)',
    '   - Data type validation (string vs number, email format, etc.)',
    '   - Boundary/edge cases (empty strings, null, max length, special characters)',
    '   - Authentication/authorization (if requires_auth is true: missing token, invalid token, expired token)',
    '   - HTTP method validation (wrong method should return 405)',
    '   - Error scenarios (server errors, database failures, etc.)',
    '   - Business logic edge cases (duplicate entries, conflicting data, etc.)',
    '',
    '4. Base your test cases on the ACTUAL CODE STRUCTURE you see in the files',
    '5. Use realistic test data that matches the code patterns (field names, data types, validation rules)',
    '',
    'Each test case MUST follow this exact schema:',
    '{',
    '  "description": "Clear description of what this test validates",',
    '  "input": {',
    '    "api": "string (exact endpoint path from code)",',
    '    "method": "GET|POST|PUT|DELETE|PATCH",',
    '    "headers": { "Authorization": "Bearer token" } (if auth required)',
    '    "body": { "field1": "value1", ... } (for POST/PUT/PATCH)',
    '  },',
    '  "expected": {',
    '    "status_code": number (200, 201, 400, 401, 404, 500, etc.)',
    '    "message": "Expected response message or error description"',
    '  }',
    '}',
    '',
    'CRITICAL: Generate 15-25 test cases minimum. Return ONLY a raw JSON array (no markdown, no code fences, no explanations).',
    '',
    '=== ENDPOINT DESCRIPTION ===',
    JSON.stringify(normalizedPayload, null, 2),
    '',
    '=== PROJECT SOURCE CODE (analyze this to understand the real implementation) ===',
    JSON.stringify(sampleFiles, null, 2),
    '',
    'Now generate the comprehensive test case array:'
  ].join('\n');

  const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-09-2025:generateContent?key=${GEMINI_API_KEY}`;

  try {
    const body = {
      contents: [
        {
          parts: [{ text: prompt }]
        }
      ]
    };

    const resp = await fetch(apiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });

    if (!resp.ok) {
      console.warn('[Gemini] API returned non-OK, falling back to rule-based tests. Status:', resp.status);
      return buildTestCases(normalizedPayload);
    }

    const data = await resp.json();
    const text = data?.candidates?.[0]?.content?.parts?.[0]?.text || '';
    
    console.log(`[Gemini] Received response (${text.length} chars). First 200 chars: ${text.substring(0, 200)}`);

    // Extract JSON from possible code fences
    let jsonText = text.trim();
    const fenceIdx = jsonText.indexOf('```');
    if (fenceIdx !== -1) {
      const match = jsonText.match(/```(?:json)?([\s\S]*?)```/i);
      if (match && match[1]) {
        jsonText = match[1].trim();
        console.log('[Gemini] Extracted JSON from code fence');
      }
    }

    let parsed;
    try {
      parsed = JSON.parse(jsonText);
      console.log(`[Gemini] Successfully parsed JSON, got ${Array.isArray(parsed) ? parsed.length : 'non-array'} items`);
    } catch (e) {
      console.warn('[Gemini] Failed to parse JSON response:', e.message);
      console.warn('[Gemini] JSON text that failed to parse (first 500 chars):', jsonText.substring(0, 500));
      return buildTestCases(normalizedPayload);
    }

    if (!Array.isArray(parsed)) {
      console.warn('[Gemini] Parsed response is not an array, falling back to rule-based tests.');
      return buildTestCases(normalizedPayload);
    }

    // Basic sanitization to ensure required fields exist
    const safeCases = parsed
      .filter(tc => tc && typeof tc === 'object')
      .map(tc => ({
        description: tc.description || 'Auto-generated test case',
        input: {
          api: tc.input?.api || normalizedPayload.api,
          method: (tc.input?.method || normalizedPayload.method || 'POST').toUpperCase(),
          headers: tc.input?.headers || undefined,
          body: tc.input?.body
        },
        expected: {
          status_code: Number(tc.expected?.status_code) || 200,
          message: tc.expected?.message || 'Request processed successfully'
        }
      }));

    if (safeCases.length === 0) {
      console.warn('[Gemini] No valid test cases after sanitization, using rule-based tests.');
      return buildTestCases(normalizedPayload);
    }

    // Ensure minimum 5-10 test cases: if Gemini returned fewer, supplement with rule-based
    const MIN_TEST_CASES = 5;
    if (safeCases.length < MIN_TEST_CASES) {
      console.log(`[Gemini] Only got ${safeCases.length} test cases, supplementing with rule-based to reach minimum ${MIN_TEST_CASES}`);
      const fallbackCases = buildTestCases(normalizedPayload);
      // Merge: use Gemini cases first, then add unique fallback cases
      const existingDescriptions = new Set(safeCases.map(tc => tc.description?.toLowerCase() || ''));
      for (const fallbackCase of fallbackCases) {
        const desc = fallbackCase.description?.toLowerCase() || '';
        if (!existingDescriptions.has(desc) && safeCases.length < MIN_TEST_CASES) {
          safeCases.push(fallbackCase);
          existingDescriptions.add(desc);
        }
      }
      console.log(`[Gemini] Final test case count: ${safeCases.length}`);
    }

    return safeCases;
  } catch (err) {
    console.warn('[Gemini] Error during test generation, falling back to rule-based tests:', err.message);
    console.error('[Gemini] Full error:', err);
    const fallbackCases = buildTestCases(normalizedPayload);
    console.log(`[Gemini] Generated ${fallbackCases.length} fallback test cases`);
    return fallbackCases;
  }
}

function normalizeTestCasePayload(payload) {
  const api = payload.api || '/';
  const method = (payload.method || 'POST').toUpperCase();
  const fields = Array.isArray(payload.fields) ? payload.fields : [];
  const authRequired = Boolean(payload.requires_auth ?? payload.auth_required ?? false);
  const metadata = typeof payload.metadata === 'object' && payload.metadata !== null ? payload.metadata : {};

  return { api, method, fields, requires_auth: authRequired, metadata };
}

function buildTestCases(payload) {
  const fieldProfiles = buildFieldProfiles(payload.fields);
  const baseBody = buildValidBody(fieldProfiles);
  const testCases = [];
  const successStatus = payload.method === 'POST' ? 201 : 200;

  testCases.push(createTestCase({
    description: "Valid input returns success response",
    payload,
    body: baseBody,
    expected: { status_code: successStatus, message: "Request processed successfully" }
  }));

  fieldProfiles.forEach(profile => {
    const missingBody = cloneBody(baseBody);
    delete missingBody[profile.name];
    testCases.push(createTestCase({
      description: `Missing ${profile.name} triggers validation error`,
      payload,
      body: missingBody,
      expected: { status_code: 400, message: `${profile.name} is required` }
    }));
  });

  fieldProfiles.forEach(profile => {
    const invalidBody = cloneBody(baseBody);
    invalidBody[profile.name] = profile.invalidValue;
    testCases.push(createTestCase({
      description: `Invalid data type for ${profile.name}`,
      payload,
      body: invalidBody,
      expected: { status_code: 400, message: `${profile.name} must be a valid ${profile.type}` }
    }));
  });

  fieldProfiles.forEach(profile => {
    profile.boundaryValues.forEach(boundary => {
      const boundaryBody = cloneBody(baseBody);
      boundaryBody[profile.name] = boundary.value;
      testCases.push(createTestCase({
        description: `${profile.name} ${boundary.label}`,
        payload,
        body: boundaryBody,
        expected: boundary.expected
      }));
    });
  });

  if (payload.requires_auth) {
    testCases.push(createTestCase({
      description: "Missing Authorization header should be rejected",
      payload,
      body: baseBody,
      headers: { Authorization: "" },
      expected: { status_code: 401, message: "Unauthorized access" }
    }));
  }

  const alternateMethod = payload.method === 'GET' ? 'POST' : 'GET';
  testCases.push({
    description: `Calling ${alternateMethod} ${payload.api} should return method not allowed`,
    input: {
      api: payload.api,
      method: alternateMethod,
      body: alternateMethod === 'GET' ? undefined : baseBody
    },
    expected: { status_code: 405, message: "Method Not Allowed" }
  });

  testCases.push(createTestCase({
    description: "Empty request body should fail validation",
    payload,
    body: {},
    expected: { status_code: 400, message: "Body cannot be empty" }
  }));

  // Add more variations to ensure minimum 5-10 test cases
  if (testCases.length < 5) {
    // Add null/undefined field tests
    fieldProfiles.forEach(profile => {
      if (testCases.length >= 10) return;
      const nullBody = cloneBody(baseBody);
      nullBody[profile.name] = null;
      testCases.push(createTestCase({
        description: `${profile.name} set to null should fail validation`,
        payload,
        body: nullBody,
        expected: { status_code: 400, message: `${profile.name} cannot be null` }
      }));
    });

    // Add extra boundary tests
    fieldProfiles.forEach(profile => {
      if (testCases.length >= 10) return;
      if (profile.type === 'string') {
        const longStringBody = cloneBody(baseBody);
        longStringBody[profile.name] = 'a'.repeat(1000);
        testCases.push(createTestCase({
          description: `${profile.name} with extremely long string should validate length`,
          payload,
          body: longStringBody,
          expected: { status_code: 400, message: `${profile.name} exceeds maximum length` }
        }));
      }
    });

    // Add multiple valid input variations
    if (testCases.length < 10 && fieldProfiles.length > 0) {
      const variationBody = cloneBody(baseBody);
      fieldProfiles.forEach(profile => {
        if (profile.name.toLowerCase().includes('email')) {
          variationBody[profile.name] = 'test2@example.com';
        } else if (profile.name.toLowerCase().includes('name')) {
          variationBody[profile.name] = 'John Doe';
        }
      });
      testCases.push(createTestCase({
        description: "Alternative valid input variation returns success",
        payload,
        body: variationBody,
        expected: { status_code: successStatus, message: "Request processed successfully" }
      }));
    }
  }

  console.log(`[buildTestCases] Generated ${testCases.length} test cases`);
  return testCases;
}

function buildFieldProfiles(fields) {
  return fields.map(field => {
    const name = typeof field === 'string' ? field : field?.name || 'field';
    const type = inferFieldType(name);
    const validValue = getSampleValidValue(name, type);
    return {
      name,
      type,
      validValue,
      invalidValue: getSampleInvalidValue(type),
      boundaryValues: buildBoundaryValues(name, type)
    };
  });
}

function buildValidBody(fieldProfiles) {
  return fieldProfiles.reduce((body, profile) => {
    body[profile.name] = profile.validValue;
    return body;
  }, {});
}

function buildBoundaryValues(name, type) {
  if (type === 'number') {
    return [
      { label: "set to zero", value: 0, expected: { status_code: 400, message: `${name} cannot be zero` } },
      { label: "set to negative value", value: -1, expected: { status_code: 400, message: `${name} must be positive` } },
      { label: "set to extremely high value", value: 1000000000, expected: { status_code: 422, message: `${name} exceeds allowed range` } }
    ];
  }

  if (type === 'boolean') {
    return [
      { label: "set to null", value: null, expected: { status_code: 400, message: `${name} must be true or false` } }
    ];
  }

  return [
    { label: "set to empty string", value: "", expected: { status_code: 400, message: `${name} cannot be empty` } },
    { label: "set to max length (256 chars)", value: 'a'.repeat(256), expected: { status_code: 422, message: `${name} exceeds maximum length` } },
    { label: "set to special characters", value: "!@#$%^&*()__TEST__", expected: { status_code: 400, message: `${name} contains unsupported characters` } }
  ];
}

function inferFieldType(name) {
  const lowered = name.toLowerCase();
  if (lowered.includes('count') || lowered.includes('id') || lowered.includes('amount') || lowered.includes('age')) return 'number';
  if (lowered.startsWith('is_') || lowered.startsWith('has_') || lowered.endsWith('_flag') || lowered.includes('enabled')) return 'boolean';
  return 'string';
}

function getSampleValidValue(name, type) {
  const lowered = name.toLowerCase();
  if (type === 'number') return 1;
  if (type === 'boolean') return true;
  if (lowered.includes('email')) return 'user@example.com';
  if (lowered.includes('password')) return 'Str0ngP@ss!';
  if (lowered.includes('token')) return 'valid-token-123';
  if (lowered.includes('username')) return 'test_user';
  return `${name}_value`;
}

function getSampleInvalidValue(type) {
  if (type === 'number') return "not-a-number";
  if (type === 'boolean') return "truthy-string";
  return 999999;
}

function createTestCase({ description, payload, body, headers, expected }) {
  const requestBody = payload.method === 'GET' ? undefined : body;
  return {
    description,
    input: {
      api: payload.api,
      method: payload.method,
      headers: headers || undefined,
      body: requestBody
    },
    expected
  };
}

function cloneBody(body) {
  return JSON.parse(JSON.stringify(body));
}

// (server start moved to guarded block at file end)

// Export app for testing and allow importing without starting the server
if (require.main !== module) {
  // when required as a module (e.g., by tests), don't start listening
  module.exports = app;
} else {
  // main module - start server
  app.listen(port, () => {
    console.log(`Agent (Smart Git LTM) listening on port ${port}`);
    console.log(`LTM Path: ${LTM_FILE_PATH}`);
  });
}