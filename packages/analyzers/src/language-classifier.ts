/**
 * Language, file-kind, and ecosystem classification for scanned files.
 * All functions are pure — no filesystem access, no network calls.
 */

// ─── Language detection ───────────────────────────────────────────────────────

const EXT_TO_LANGUAGE: Record<string, string> = {
  '.ts': 'typescript', '.tsx': 'typescript',
  '.js': 'javascript', '.jsx': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript',
  '.py': 'python', '.pyw': 'python',
  '.go': 'go',
  '.java': 'java',
  '.cs': 'csharp',
  '.php': 'php',
  '.rb': 'ruby',
  '.rs': 'rust',
  '.kt': 'kotlin', '.kts': 'kotlin',
  '.swift': 'swift',
  '.c': 'c', '.h': 'c',
  '.cpp': 'cpp', '.cc': 'cpp', '.cxx': 'cpp', '.hpp': 'cpp',
  '.scala': 'scala',
  '.clj': 'clojure', '.cljs': 'clojure',
  '.ex': 'elixir', '.exs': 'elixir',
  '.erl': 'erlang', '.hrl': 'erlang',
  '.fs': 'fsharp', '.fsx': 'fsharp',
  '.sh': 'shell', '.bash': 'shell', '.zsh': 'shell', '.fish': 'shell',
  '.ps1': 'powershell',
  '.bat': 'batch', '.cmd': 'batch',
  '.make': 'makefile', '.mk': 'makefile',
  '.tf': 'terraform', '.tfvars': 'terraform',
  '.hcl': 'hcl', '.nomad': 'hcl',
  '.rego': 'rego',
  '.cue': 'cue',
  '.yaml': 'yaml', '.yml': 'yaml',
  '.json': 'json', '.jsonc': 'json',
  '.toml': 'toml',
  '.ini': 'ini',
  '.conf': 'config', '.config': 'config', '.properties': 'config',
  '.xml': 'xml',
  '.env': 'env', '.envrc': 'env',
  '.sql': 'sql',
  '.graphql': 'graphql', '.gql': 'graphql',
  '.prisma': 'prisma',
  '.dbml': 'dbml',
  '.html': 'html', '.htm': 'html',
  '.css': 'css', '.scss': 'css', '.sass': 'css', '.less': 'css',
  '.vue': 'vue',
  '.svelte': 'svelte',
  '.astro': 'astro',
  '.md': 'markdown', '.mdx': 'markdown',
  '.txt': 'text', '.rst': 'text',
  '.pem': 'pem', '.key': 'pem', '.crt': 'pem', '.cert': 'pem', '.pub': 'pem',
  '.rules': 'security_rules',
};

const BASENAME_TO_LANGUAGE: Record<string, string> = {
  'Dockerfile': 'dockerfile', 'Containerfile': 'dockerfile',
  'Makefile': 'makefile', 'GNUmakefile': 'makefile',
  'Jenkinsfile': 'groovy',
  'Procfile': 'text',
  'Gemfile': 'ruby', 'Rakefile': 'ruby',
  'Pipfile': 'toml',
  'requirements.txt': 'text', 'requirements-dev.txt': 'text', 'poetry.lock': 'text',
  'pyproject.toml': 'toml',
  'go.mod': 'go', 'go.sum': 'text',
  'Cargo.toml': 'toml', 'Cargo.lock': 'text',
  'pom.xml': 'xml',
  'build.gradle': 'groovy', 'build.gradle.kts': 'kotlin',
  'settings.gradle': 'groovy', 'settings.gradle.kts': 'kotlin',
  'gradle.properties': 'config',
  'composer.json': 'json', 'composer.lock': 'json',
  'package.json': 'json', 'package-lock.json': 'json',
  'pnpm-lock.yaml': 'yaml', 'yarn.lock': 'text', 'bun.lockb': 'text',
  'deno.json': 'json', 'deno.jsonc': 'json',
  'tsconfig.json': 'json',
  'next.config.js': 'javascript', 'next.config.mjs': 'javascript', 'next.config.ts': 'typescript',
  'vite.config.ts': 'typescript', 'vite.config.js': 'javascript',
  'nuxt.config.ts': 'typescript', 'svelte.config.js': 'javascript', 'astro.config.mjs': 'javascript',
  'vercel.json': 'json', 'netlify.toml': 'toml', 'wrangler.toml': 'toml',
  'firebase.json': 'json', 'firestore.rules': 'security_rules', 'storage.rules': 'security_rules',
  'nginx.conf': 'config', 'httpd.conf': 'config', 'apache.conf': 'config', 'Caddyfile': 'config',
  'robots.txt': 'text', 'sitemap.xml': 'xml',
};

// ─── File-kind detection ──────────────────────────────────────────────────────

const EXT_TO_FILEKIND: Record<string, string> = {
  '.ts': 'source', '.tsx': 'source', '.js': 'source', '.jsx': 'source', '.mjs': 'source', '.cjs': 'source',
  '.py': 'source', '.go': 'source', '.java': 'source', '.cs': 'source', '.php': 'source',
  '.rb': 'source', '.rs': 'source', '.kt': 'source', '.kts': 'source', '.swift': 'source',
  '.c': 'source', '.cpp': 'source', '.cc': 'source', '.cxx': 'source', '.h': 'source', '.hpp': 'source',
  '.scala': 'source', '.clj': 'source', '.ex': 'source', '.exs': 'source', '.erl': 'source',
  '.hrl': 'source', '.fs': 'source', '.fsx': 'source',
  '.vue': 'source', '.svelte': 'source', '.astro': 'source',
  '.html': 'source', '.htm': 'source',
  '.css': 'source', '.scss': 'source', '.sass': 'source', '.less': 'source',
  '.tf': 'infrastructure', '.tfvars': 'infrastructure', '.hcl': 'infrastructure', '.nomad': 'infrastructure',
  '.rego': 'security_rules', '.cue': 'config',
  '.yaml': 'config', '.yml': 'config',
  '.json': 'config', '.jsonc': 'config',
  '.toml': 'config', '.ini': 'config', '.conf': 'config', '.config': 'config', '.properties': 'config', '.xml': 'config',
  '.env': 'env', '.envrc': 'env',
  '.sql': 'database', '.graphql': 'database', '.gql': 'database', '.prisma': 'database', '.dbml': 'database',
  '.sh': 'script', '.bash': 'script', '.zsh': 'script', '.fish': 'script',
  '.ps1': 'script', '.bat': 'script', '.cmd': 'script', '.make': 'script', '.mk': 'script',
  '.md': 'documentation', '.mdx': 'documentation', '.txt': 'documentation', '.rst': 'documentation',
  '.pem': 'certificate_or_key', '.key': 'certificate_or_key', '.crt': 'certificate_or_key',
  '.cert': 'certificate_or_key', '.pub': 'certificate_or_key',
  '.rules': 'security_rules',
};

const BASENAME_TO_FILEKIND: Record<string, string> = {
  'Dockerfile': 'docker', 'Containerfile': 'docker',
  'docker-compose.yml': 'docker', 'docker-compose.yaml': 'docker',
  'compose.yml': 'docker', 'compose.yaml': 'docker',
  'Makefile': 'script', 'GNUmakefile': 'script',
  'Jenkinsfile': 'ci_cd',
  'Procfile': 'config',
  'package.json': 'dependency_manifest',
  'package-lock.json': 'lockfile', 'pnpm-lock.yaml': 'lockfile', 'yarn.lock': 'lockfile', 'bun.lockb': 'lockfile',
  'requirements.txt': 'dependency_manifest', 'requirements-dev.txt': 'dependency_manifest',
  'Pipfile': 'dependency_manifest', 'poetry.lock': 'lockfile', 'pyproject.toml': 'dependency_manifest',
  'go.mod': 'dependency_manifest', 'go.sum': 'lockfile',
  'Cargo.toml': 'dependency_manifest', 'Cargo.lock': 'lockfile',
  'pom.xml': 'dependency_manifest',
  'build.gradle': 'dependency_manifest', 'build.gradle.kts': 'dependency_manifest',
  'settings.gradle': 'dependency_manifest', 'settings.gradle.kts': 'dependency_manifest',
  'composer.json': 'dependency_manifest', 'composer.lock': 'lockfile',
  'Gemfile': 'dependency_manifest',
  'firestore.rules': 'security_rules', 'storage.rules': 'security_rules',
  'next.config.js': 'framework_config', 'next.config.mjs': 'framework_config', 'next.config.ts': 'framework_config',
  'vite.config.ts': 'framework_config', 'vite.config.js': 'framework_config',
  'nuxt.config.ts': 'framework_config', 'svelte.config.js': 'framework_config', 'astro.config.mjs': 'framework_config',
  'vercel.json': 'framework_config', 'netlify.toml': 'framework_config', 'wrangler.toml': 'framework_config',
  'firebase.json': 'framework_config',
  'tsconfig.json': 'framework_config',
  'nginx.conf': 'config', 'httpd.conf': 'config', 'apache.conf': 'config', 'Caddyfile': 'config',
};

// ─── Ecosystem detection ──────────────────────────────────────────────────────

const BASENAME_TO_ECOSYSTEM: Record<string, string> = {
  // Node / JS tooling
  'package.json': 'node', 'package-lock.json': 'node', 'pnpm-lock.yaml': 'node',
  'yarn.lock': 'node', 'bun.lockb': 'node', 'deno.json': 'node', 'deno.jsonc': 'node',
  'tsconfig.json': 'node',
  'next.config.js': 'node', 'next.config.mjs': 'node', 'next.config.ts': 'node',
  'vite.config.ts': 'node', 'vite.config.js': 'node',
  'nuxt.config.ts': 'node', 'svelte.config.js': 'node', 'astro.config.mjs': 'node',
  // Python
  'requirements.txt': 'python', 'requirements-dev.txt': 'python',
  'Pipfile': 'python', 'poetry.lock': 'python', 'pyproject.toml': 'python',
  // Go
  'go.mod': 'go', 'go.sum': 'go',
  // Java / JVM
  'pom.xml': 'java', 'build.gradle': 'java', 'build.gradle.kts': 'java',
  'settings.gradle': 'java', 'settings.gradle.kts': 'java', 'gradle.properties': 'java',
  // Rust
  'Cargo.toml': 'rust', 'Cargo.lock': 'rust',
  // PHP
  'composer.json': 'php', 'composer.lock': 'php',
  // Ruby
  'Gemfile': 'ruby', 'Rakefile': 'ruby',
  // Docker
  'Dockerfile': 'docker', 'Containerfile': 'docker',
  'docker-compose.yml': 'docker', 'docker-compose.yaml': 'docker',
  'compose.yml': 'docker', 'compose.yaml': 'docker',
  // CI/CD
  'Jenkinsfile': 'jenkins',
  '.gitlab-ci.yml': 'gitlab-ci',
  'azure-pipelines.yml': 'azure-pipelines',
  'bitbucket-pipelines.yml': 'bitbucket-pipelines',
  '.travis.yml': 'travis-ci',
  '.drone.yml': 'drone-ci', 'drone.yml': 'drone-ci',
  // Cloud
  'vercel.json': 'vercel',
  'netlify.toml': 'netlify',
  'wrangler.toml': 'cloudflare',
  'firebase.json': 'firebase', 'firestore.rules': 'firebase', 'storage.rules': 'firebase',
};

// ─── Public API ───────────────────────────────────────────────────────────────

export function detectLanguage(relativePath: string, extension: string, basename: string): string {
  if (BASENAME_TO_LANGUAGE[basename]) return BASENAME_TO_LANGUAGE[basename];
  if (EXT_TO_LANGUAGE[extension]) return EXT_TO_LANGUAGE[extension];
  // .env.local, .env.production, etc.
  if (basename.startsWith('.env')) return 'env';
  return 'unknown';
}

export function detectFileKind(relativePath: string, extension: string, basename: string): string {
  const lower = relativePath.toLowerCase();

  // CI/CD paths take priority over extension
  if (
    lower.includes('.github/workflows/') ||
    lower.includes('.github/actions/') ||
    lower.includes('.circleci/') ||
    basename === '.gitlab-ci.yml' ||
    basename === 'azure-pipelines.yml' ||
    basename === 'bitbucket-pipelines.yml' ||
    basename === '.travis.yml' ||
    basename === '.drone.yml' ||
    basename === 'drone.yml' ||
    basename === 'Jenkinsfile'
  ) {
    return 'ci_cd';
  }

  if (BASENAME_TO_FILEKIND[basename]) return BASENAME_TO_FILEKIND[basename];

  // .env.* variants
  if (basename.startsWith('.env')) return 'env';

  if (EXT_TO_FILEKIND[extension]) return EXT_TO_FILEKIND[extension];
  return 'source';
}

export function detectEcosystem(relativePath: string, basename: string): string | undefined {
  const lower = relativePath.toLowerCase();

  // Path-based CI/CD detection (must come first to handle *.yml in workflow dirs)
  if (lower.includes('.github/workflows/') || lower.includes('.github/actions/')) return 'github-actions';
  if (lower.includes('.circleci/')) return 'circleci';

  // Basename-based ecosystem
  if (BASENAME_TO_ECOSYSTEM[basename]) return BASENAME_TO_ECOSYSTEM[basename];

  // Terraform by extension or path
  if (lower.includes('/terraform/') || lower.includes('/infra/') || lower.endsWith('.tf') || lower.endsWith('.tfvars')) return 'terraform';

  // Kubernetes by path conventions
  if (lower.includes('/k8s/') || lower.includes('/kubernetes/') || lower.includes('/helm/') || lower.includes('/charts/')) return 'kubernetes';

  // Supabase by path
  if (lower.includes('supabase/')) return 'supabase';

  return undefined;
}
