import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { detectLanguage, detectFileKind, detectEcosystem } from '../language-classifier';

// ─── detectLanguage ───────────────────────────────────────────────────────────

describe('detectLanguage', () => {
  test('TypeScript source file', () => {
    assert.equal(detectLanguage('src/index.ts', '.ts', 'index.ts'), 'typescript');
  });
  test('Python source file', () => {
    assert.equal(detectLanguage('app/main.py', '.py', 'main.py'), 'python');
  });
  test('Go source file', () => {
    assert.equal(detectLanguage('main.go', '.go', 'main.go'), 'go');
  });
  test('Java source file', () => {
    assert.equal(detectLanguage('src/App.java', '.java', 'App.java'), 'java');
  });
  test('Rust source file', () => {
    assert.equal(detectLanguage('src/main.rs', '.rs', 'main.rs'), 'rust');
  });
  test('PHP source file', () => {
    assert.equal(detectLanguage('index.php', '.php', 'index.php'), 'php');
  });
  test('Ruby source file', () => {
    assert.equal(detectLanguage('app.rb', '.rb', 'app.rb'), 'ruby');
  });
  test('C# source file', () => {
    assert.equal(detectLanguage('Program.cs', '.cs', 'Program.cs'), 'csharp');
  });
  test('Kotlin source file', () => {
    assert.equal(detectLanguage('Main.kt', '.kt', 'Main.kt'), 'kotlin');
  });
  test('Swift source file', () => {
    assert.equal(detectLanguage('App.swift', '.swift', 'App.swift'), 'swift');
  });
  test('C source file', () => {
    assert.equal(detectLanguage('main.c', '.c', 'main.c'), 'c');
  });
  test('C++ source file', () => {
    assert.equal(detectLanguage('main.cpp', '.cpp', 'main.cpp'), 'cpp');
  });
  test('Dockerfile by basename', () => {
    assert.equal(detectLanguage('Dockerfile', '', 'Dockerfile'), 'dockerfile');
  });
  test('Containerfile by basename', () => {
    assert.equal(detectLanguage('Containerfile', '', 'Containerfile'), 'dockerfile');
  });
  test('Makefile by basename', () => {
    assert.equal(detectLanguage('Makefile', '', 'Makefile'), 'makefile');
  });
  test('Jenkinsfile by basename', () => {
    assert.equal(detectLanguage('Jenkinsfile', '', 'Jenkinsfile'), 'groovy');
  });
  test('Terraform .tf file', () => {
    assert.equal(detectLanguage('main.tf', '.tf', 'main.tf'), 'terraform');
  });
  test('Shell script', () => {
    assert.equal(detectLanguage('build.sh', '.sh', 'build.sh'), 'shell');
  });
  test('YAML file', () => {
    assert.equal(detectLanguage('docker-compose.yml', '.yml', 'docker-compose.yml'), 'yaml');
  });
  test('.env file by extension', () => {
    assert.equal(detectLanguage('.env', '.env', '.env'), 'env');
  });
  test('.env.local by basename prefix', () => {
    assert.equal(detectLanguage('.env.local', '', '.env.local'), 'env');
  });
  test('firestore.rules by basename', () => {
    assert.equal(detectLanguage('firestore.rules', '.rules', 'firestore.rules'), 'security_rules');
  });
  test('go.mod by basename', () => {
    assert.equal(detectLanguage('go.mod', '', 'go.mod'), 'go');
  });
  test('package.json by basename', () => {
    assert.equal(detectLanguage('package.json', '.json', 'package.json'), 'json');
  });
  test('requirements.txt by basename', () => {
    assert.equal(detectLanguage('requirements.txt', '.txt', 'requirements.txt'), 'text');
  });
});

// ─── detectFileKind ───────────────────────────────────────────────────────────

describe('detectFileKind', () => {
  test('Python source → source', () => {
    assert.equal(detectFileKind('app/main.py', '.py', 'main.py'), 'source');
  });
  test('Dockerfile → docker', () => {
    assert.equal(detectFileKind('Dockerfile', '', 'Dockerfile'), 'docker');
  });
  test('docker-compose.yml → docker', () => {
    assert.equal(detectFileKind('docker-compose.yml', '.yml', 'docker-compose.yml'), 'docker');
  });
  test('Makefile → script', () => {
    assert.equal(detectFileKind('Makefile', '', 'Makefile'), 'script');
  });
  test('Jenkinsfile → ci_cd', () => {
    assert.equal(detectFileKind('Jenkinsfile', '', 'Jenkinsfile'), 'ci_cd');
  });
  test('.github/workflows/ci.yml → ci_cd', () => {
    assert.equal(detectFileKind('.github/workflows/ci.yml', '.yml', 'ci.yml'), 'ci_cd');
  });
  test('.github/actions/build.yml → ci_cd', () => {
    assert.equal(detectFileKind('.github/actions/build.yml', '.yml', 'build.yml'), 'ci_cd');
  });
  test('.circleci/config.yml → ci_cd', () => {
    assert.equal(detectFileKind('.circleci/config.yml', '.yml', 'config.yml'), 'ci_cd');
  });
  test('.gitlab-ci.yml → ci_cd (basename)', () => {
    assert.equal(detectFileKind('.gitlab-ci.yml', '.yml', '.gitlab-ci.yml'), 'ci_cd');
  });
  test('azure-pipelines.yml → ci_cd', () => {
    assert.equal(detectFileKind('azure-pipelines.yml', '.yml', 'azure-pipelines.yml'), 'ci_cd');
  });
  test('main.tf → infrastructure', () => {
    assert.equal(detectFileKind('main.tf', '.tf', 'main.tf'), 'infrastructure');
  });
  test('terraform.tfvars → infrastructure', () => {
    assert.equal(detectFileKind('terraform.tfvars', '.tfvars', 'terraform.tfvars'), 'infrastructure');
  });
  test('schema.sql → database', () => {
    assert.equal(detectFileKind('db/schema.sql', '.sql', 'schema.sql'), 'database');
  });
  test('schema.graphql → database', () => {
    assert.equal(detectFileKind('schema.graphql', '.graphql', 'schema.graphql'), 'database');
  });
  test('package.json → dependency_manifest', () => {
    assert.equal(detectFileKind('package.json', '.json', 'package.json'), 'dependency_manifest');
  });
  test('pnpm-lock.yaml → lockfile', () => {
    assert.equal(detectFileKind('pnpm-lock.yaml', '.yaml', 'pnpm-lock.yaml'), 'lockfile');
  });
  test('yarn.lock → lockfile', () => {
    assert.equal(detectFileKind('yarn.lock', '', 'yarn.lock'), 'lockfile');
  });
  test('go.mod → dependency_manifest', () => {
    assert.equal(detectFileKind('go.mod', '', 'go.mod'), 'dependency_manifest');
  });
  test('Cargo.toml → dependency_manifest', () => {
    assert.equal(detectFileKind('Cargo.toml', '.toml', 'Cargo.toml'), 'dependency_manifest');
  });
  test('Gemfile → dependency_manifest', () => {
    assert.equal(detectFileKind('Gemfile', '', 'Gemfile'), 'dependency_manifest');
  });
  test('next.config.ts → framework_config', () => {
    assert.equal(detectFileKind('next.config.ts', '.ts', 'next.config.ts'), 'framework_config');
  });
  test('firestore.rules → security_rules', () => {
    assert.equal(detectFileKind('firestore.rules', '.rules', 'firestore.rules'), 'security_rules');
  });
  test('.env.local → env (basename prefix)', () => {
    assert.equal(detectFileKind('.env.local', '', '.env.local'), 'env');
  });
  test('.env → env', () => {
    assert.equal(detectFileKind('.env', '.env', '.env'), 'env');
  });
  test('build.sh → script', () => {
    assert.equal(detectFileKind('scripts/build.sh', '.sh', 'build.sh'), 'script');
  });
  test('README.md → documentation', () => {
    assert.equal(detectFileKind('README.md', '.md', 'README.md'), 'documentation');
  });
  test('.pem certificate → certificate_or_key', () => {
    assert.equal(detectFileKind('certs/server.pem', '.pem', 'server.pem'), 'certificate_or_key');
  });
});

// ─── detectEcosystem ─────────────────────────────────────────────────────────

describe('detectEcosystem', () => {
  test('.github/workflows/ → github-actions', () => {
    assert.equal(detectEcosystem('.github/workflows/ci.yml', 'ci.yml'), 'github-actions');
  });
  test('.github/actions/ → github-actions', () => {
    assert.equal(detectEcosystem('.github/actions/build/action.yml', 'action.yml'), 'github-actions');
  });
  test('.circleci/config.yml → circleci', () => {
    assert.equal(detectEcosystem('.circleci/config.yml', 'config.yml'), 'circleci');
  });
  test('.gitlab-ci.yml → gitlab-ci', () => {
    assert.equal(detectEcosystem('.gitlab-ci.yml', '.gitlab-ci.yml'), 'gitlab-ci');
  });
  test('azure-pipelines.yml → azure-pipelines', () => {
    assert.equal(detectEcosystem('azure-pipelines.yml', 'azure-pipelines.yml'), 'azure-pipelines');
  });
  test('Jenkinsfile → jenkins', () => {
    assert.equal(detectEcosystem('Jenkinsfile', 'Jenkinsfile'), 'jenkins');
  });
  test('package.json → node', () => {
    assert.equal(detectEcosystem('package.json', 'package.json'), 'node');
  });
  test('requirements.txt → python', () => {
    assert.equal(detectEcosystem('requirements.txt', 'requirements.txt'), 'python');
  });
  test('go.mod → go', () => {
    assert.equal(detectEcosystem('go.mod', 'go.mod'), 'go');
  });
  test('pom.xml → java', () => {
    assert.equal(detectEcosystem('pom.xml', 'pom.xml'), 'java');
  });
  test('Cargo.toml → rust', () => {
    assert.equal(detectEcosystem('Cargo.toml', 'Cargo.toml'), 'rust');
  });
  test('composer.json → php', () => {
    assert.equal(detectEcosystem('composer.json', 'composer.json'), 'php');
  });
  test('Gemfile → ruby', () => {
    assert.equal(detectEcosystem('Gemfile', 'Gemfile'), 'ruby');
  });
  test('Dockerfile → docker', () => {
    assert.equal(detectEcosystem('Dockerfile', 'Dockerfile'), 'docker');
  });
  test('docker-compose.yml → docker', () => {
    assert.equal(detectEcosystem('docker-compose.yml', 'docker-compose.yml'), 'docker');
  });
  test('vercel.json → vercel', () => {
    assert.equal(detectEcosystem('vercel.json', 'vercel.json'), 'vercel');
  });
  test('netlify.toml → netlify', () => {
    assert.equal(detectEcosystem('netlify.toml', 'netlify.toml'), 'netlify');
  });
  test('wrangler.toml → cloudflare', () => {
    assert.equal(detectEcosystem('wrangler.toml', 'wrangler.toml'), 'cloudflare');
  });
  test('firebase.json → firebase', () => {
    assert.equal(detectEcosystem('firebase.json', 'firebase.json'), 'firebase');
  });
  test('firestore.rules → firebase', () => {
    assert.equal(detectEcosystem('firestore.rules', 'firestore.rules'), 'firebase');
  });
  test('supabase/config.toml → supabase', () => {
    assert.equal(detectEcosystem('supabase/config.toml', 'config.toml'), 'supabase');
  });
  test('/k8s/deployment.yaml → kubernetes', () => {
    assert.equal(detectEcosystem('infra/k8s/deployment.yaml', 'deployment.yaml'), 'kubernetes');
  });
  test('main.tf → terraform (by extension path)', () => {
    assert.equal(detectEcosystem('main.tf', 'main.tf'), 'terraform');
  });
  test('plain TypeScript file → undefined', () => {
    assert.equal(detectEcosystem('src/utils.ts', 'utils.ts'), undefined);
  });
});
