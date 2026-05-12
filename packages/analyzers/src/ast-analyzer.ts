import type { ScannedFile, DangerousCall, UserInputSource } from '@cybermat/shared';

export interface AstAnalysisResult {
  sinks: DangerousCall[];
  sources: UserInputSource[];
}

// ── Sink patterns ─────────────────────────────────────────────────────────────

interface SinkPattern {
  re: RegExp;
  name: string;
  sinkType: DangerousCall['sinkType'];
}

const SINK_PATTERNS: SinkPattern[] = [
  // XSS sinks
  { re: /dangerouslySetInnerHTML\s*=\s*\{/, name: 'dangerouslySetInnerHTML', sinkType: 'xss' },
  { re: /\.innerHTML\s*=(?!=)/, name: 'innerHTML assignment', sinkType: 'xss' },
  { re: /\.outerHTML\s*=(?!=)/, name: 'outerHTML assignment', sinkType: 'xss' },
  { re: /\.insertAdjacentHTML\s*\(/, name: 'insertAdjacentHTML', sinkType: 'xss' },
  { re: /document\.write\s*\(/, name: 'document.write', sinkType: 'xss' },

  // Code execution
  { re: /(?<!\w)eval\s*\(/, name: 'eval()', sinkType: 'xss' },
  { re: /new\s+Function\s*\(/, name: 'new Function()', sinkType: 'xss' },
  { re: /setTimeout\s*\(\s*['"`]/, name: 'setTimeout(string)', sinkType: 'xss' },
  { re: /setInterval\s*\(\s*['"`]/, name: 'setInterval(string)', sinkType: 'xss' },

  // Command execution
  { re: /(?:exec|execSync)\s*\(/, name: 'exec/execSync', sinkType: 'command' },
  { re: /spawn\s*\([^)]*shell\s*:\s*true/, name: 'spawn with shell:true', sinkType: 'command' },
  { re: /child_process\.exec/, name: 'child_process.exec', sinkType: 'command' },

  // SQL injection
  { re: /\.\$queryRawUnsafe\s*\(/, name: 'Prisma.$queryRawUnsafe', sinkType: 'sql' },
  { re: /\.\$executeRawUnsafe\s*\(/, name: 'Prisma.$executeRawUnsafe', sinkType: 'sql' },
  { re: /(?:SELECT|INSERT|UPDATE|DELETE).*\+\s*(?:req\.|request\.|params\.|query\.|body\.|\$\{)/i, name: 'SQL string concatenation', sinkType: 'sql' },
  { re: /sequelize\.query\s*\([^)]*\+/, name: 'Sequelize raw query with concat', sinkType: 'sql' },

  // SSRF
  { re: /fetch\s*\(\s*(?!['"`])/, name: 'fetch(variable)', sinkType: 'ssrf' },
  { re: /axios\.(?:get|post|put|patch|delete)\s*\(\s*(?!['"`])/, name: 'axios(variable)', sinkType: 'ssrf' },
  { re: /got\s*\(\s*(?!['"`])/, name: 'got(variable)', sinkType: 'ssrf' },

  // Open redirect
  { re: /redirect\s*\(\s*(?:req\.|request\.|params\.|searchParams\.|body\.|query\.)/, name: 'redirect(userInput)', sinkType: 'redirect' },
  { re: /res\.redirect\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.)/, name: 'res.redirect(userInput)', sinkType: 'redirect' },
  { re: /NextResponse\.redirect\s*\(\s*(?!new\s+URL)/, name: 'NextResponse.redirect(variable)', sinkType: 'redirect' },

  // Filesystem
  { re: /fs\.(?:readFile|writeFile|appendFile|unlink|rm|mkdir)\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.|\$\{)/, name: 'fs operation with user input', sinkType: 'filesystem' },
  { re: /path\.join\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.)/, name: 'path.join with user input', sinkType: 'filesystem' },

  // AI output sinks
  { re: /(?:aiResponse|llmOutput|modelOutput|completion|generatedHtml|assistantMessage|aiContent|llmResponse|chatResponse|gptResponse)[^;]*(?:innerHTML|dangerouslySetInnerHTML)/, name: 'AI output to HTML sink', sinkType: 'ai-output' },
];

// ── Source patterns ───────────────────────────────────────────────────────────

interface SourcePattern {
  re: RegExp;
  name: string;
  sourceType: UserInputSource['sourceType'];
}

const SOURCE_PATTERNS: SourcePattern[] = [
  // Next.js app router
  { re: /(?:await\s+)?request\.json\s*\(\s*\)/, name: 'request.json()', sourceType: 'request-body' },
  { re: /(?:await\s+)?request\.formData\s*\(\s*\)/, name: 'request.formData()', sourceType: 'request-body' },
  { re: /(?:await\s+)?request\.text\s*\(\s*\)/, name: 'request.text()', sourceType: 'request-body' },
  { re: /searchParams\.get\s*\(/, name: 'searchParams.get()', sourceType: 'request-query' },
  { re: /\bparams\.\w+/, name: 'params (route params)', sourceType: 'request-params' },
  { re: /cookies\(\)\.get/, name: 'cookies().get()', sourceType: 'cookie' },
  { re: /headers\(\)\.get/, name: 'headers().get()', sourceType: 'request-body' },

  // Express
  { re: /req\.body/, name: 'req.body', sourceType: 'request-body' },
  { re: /req\.query/, name: 'req.query', sourceType: 'request-query' },
  { re: /req\.params/, name: 'req.params', sourceType: 'request-params' },
  { re: /req\.headers/, name: 'req.headers', sourceType: 'request-body' },
  { re: /req\.cookies/, name: 'req.cookies', sourceType: 'cookie' },

  // Browser APIs
  { re: /location\.search/, name: 'location.search', sourceType: 'url-search-params' },
  { re: /location\.hash/, name: 'location.hash', sourceType: 'browser-location' },
  { re: /new\s+URLSearchParams/, name: 'URLSearchParams', sourceType: 'url-search-params' },
  { re: /localStorage\.getItem/, name: 'localStorage.getItem', sourceType: 'storage' },
  { re: /sessionStorage\.getItem/, name: 'sessionStorage.getItem', sourceType: 'storage' },
  { re: /document\.cookie/, name: 'document.cookie', sourceType: 'cookie' },
  { re: /event\.data/, name: 'message event.data (postMessage)', sourceType: 'post-message' },

  // File upload
  { re: /req\.file|req\.files|formData\.get\s*\(['"]file/, name: 'file upload', sourceType: 'file-upload' },
];

/** Extensions safe to feed into the JS/TS parser. Non-JS files must never enter this path. */
const JS_TS_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs']);

export function analyzeAst(files: ScannedFile[]): AstAnalysisResult {
  const sinks: DangerousCall[] = [];
  const sources: UserInputSource[] = [];

  for (const file of files) {
    if (!JS_TS_EXTENSIONS.has(file.extension)) continue;

    const lines = file.content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('*')) continue;

      // Check sinks
      for (const pattern of SINK_PATTERNS) {
        if (pattern.re.test(line)) {
          const colMatch = line.match(pattern.re);
          sinks.push({
            name: pattern.name,
            file: file.relativePath,
            line: i + 1,
            column: colMatch ? line.indexOf(colMatch[0]) : undefined,
            sinkType: pattern.sinkType,
            argumentPreview: line.trim().slice(0, 80),
          });
          break; // one sink type per line
        }
      }

      // Check sources
      for (const pattern of SOURCE_PATTERNS) {
        if (pattern.re.test(line)) {
          sources.push({
            name: pattern.name,
            file: file.relativePath,
            line: i + 1,
            sourceType: pattern.sourceType,
          });
          break; // one source type per line
        }
      }
    }
  }

  return { sinks, sources };
}
