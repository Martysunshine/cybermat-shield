import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { scanFileForPatterns } from '../index';
import type { ScannedFile } from '@cybermat/shared';

function makeFile(relativePath: string, content: string, language: string, fileKind = 'source'): ScannedFile {
  return {
    path: `/tmp/${relativePath}`,
    relativePath,
    extension: relativePath.includes('.') ? `.${relativePath.split('.').pop()}` : '',
    sizeBytes: Buffer.byteLength(content),
    content,
    language,
    fileKind,
  };
}

// ─── Docker ───────────────────────────────────────────────────────────────────

describe('multilang-engine — Docker', () => {
  test('detects curl|sh in Dockerfile', () => {
    const file = makeFile('Dockerfile', `
      RUN curl -fsSL https://example.com/install.sh | sh
    `, 'dockerfile');
    const findings = scanFileForPatterns(file);
    const found = findings.find(f => f.ruleId === 'docker.curl-pipe-sh');
    assert.ok(found, 'Should detect curl|sh in Dockerfile');
    assert.equal(found!.severity, 'high');
  });

  test('detects ADD with remote URL', () => {
    const file = makeFile('Dockerfile', `
      ADD https://example.com/archive.tar.gz /app/
    `, 'dockerfile');
    const findings = scanFileForPatterns(file);
    const found = findings.find(f => f.ruleId === 'docker.add-remote-url');
    assert.ok(found, 'Should detect ADD with remote URL');
    assert.equal(found!.severity, 'medium');
  });

  test('detects secret in ENV', () => {
    const file = makeFile('Dockerfile', `
      ENV DATABASE_PASSWORD=supersecret123
    `, 'dockerfile');
    const findings = scanFileForPatterns(file);
    const found = findings.find(f => f.ruleId === 'docker.secret-in-env');
    assert.ok(found, 'Should detect secret in ENV');
  });

  test('detects privileged: true in compose YAML', () => {
    const file = makeFile('docker-compose.yml', `
services:
  app:
    privileged: true
    `, 'yaml', 'docker');
    const findings = scanFileForPatterns(file);
    const found = findings.find(f => f.ruleId === 'docker.privileged-container');
    assert.ok(found, 'Should detect privileged: true in docker compose');
  });

  test('detects docker.sock mount', () => {
    const file = makeFile('docker-compose.yml', `
      volumes:
        - /var/run/docker.sock:/var/run/docker.sock
    `, 'yaml', 'docker');
    const findings = scanFileForPatterns(file);
    const found = findings.find(f => f.ruleId === 'docker.docker-sock-mount');
    assert.ok(found, 'Should detect docker socket mount');
  });

  test('detects host network mode', () => {
    const file = makeFile('docker-compose.yml', `
      network_mode: host
    `, 'yaml', 'docker');
    const findings = scanFileForPatterns(file);
    const found = findings.find(f => f.ruleId === 'docker.host-network');
    assert.ok(found, 'Should detect host network mode');
  });

  test('no finding for commented-out curl|sh', () => {
    const file = makeFile('Dockerfile', `
      # RUN curl https://example.com/install.sh | sh
    `, 'dockerfile');
    const findings = scanFileForPatterns(file);
    const found = findings.find(f => f.ruleId === 'docker.curl-pipe-sh');
    assert.equal(found, undefined, 'Should not flag commented lines');
  });
});

// ─── Shell ────────────────────────────────────────────────────────────────────

describe('multilang-engine — Shell', () => {
  test('detects curl|sh in shell script', () => {
    const file = makeFile('install.sh', `
      curl -fsSL https://example.com/install.sh | bash
    `, 'shell');
    const findings = scanFileForPatterns(file);
    const found = findings.find(f => f.ruleId === 'shell.curl-pipe-sh');
    assert.ok(found, 'Should detect curl|bash pattern');
  });

  test('detects eval in shell script', () => {
    const file = makeFile('build.sh', `
      eval "$(some-command)"
    `, 'shell');
    const findings = scanFileForPatterns(file);
    const found = findings.find(f => f.ruleId === 'shell.eval-usage');
    assert.ok(found, 'Should detect eval usage');
  });

  test('detects chmod 777', () => {
    const file = makeFile('setup.sh', `
      chmod 777 /var/www/html
    `, 'shell');
    const findings = scanFileForPatterns(file);
    const found = findings.find(f => f.ruleId === 'shell.insecure-chmod');
    assert.ok(found, 'Should detect chmod 777');
  });

  test('detects curl -k (TLS disabled)', () => {
    const file = makeFile('fetch.sh', `
      curl -k https://api.example.com/data
    `, 'shell');
    const findings = scanFileForPatterns(file);
    const found = findings.find(f => f.ruleId === 'shell.tls-disabled-curl');
    assert.ok(found, 'Should detect curl -k');
  });

  test('detects wget --no-check-certificate', () => {
    const file = makeFile('download.sh', `
      wget --no-check-certificate https://example.com/file.tar.gz
    `, 'shell');
    const findings = scanFileForPatterns(file);
    const found = findings.find(f => f.ruleId === 'shell.tls-disabled-wget');
    assert.ok(found, 'Should detect wget --no-check-certificate');
  });

  test('no finding for # commented eval line', () => {
    const file = makeFile('build.sh', `
      # eval "$(dangerous)"
    `, 'shell');
    const findings = scanFileForPatterns(file);
    const found = findings.find(f => f.ruleId === 'shell.eval-usage');
    assert.equal(found, undefined, 'Should not flag hash-commented lines');
  });
});

// ─── Kubernetes ───────────────────────────────────────────────────────────────

describe('multilang-engine — Kubernetes', () => {
  test('detects privileged: true → critical', () => {
    const file = makeFile('k8s/deployment.yaml', `
      securityContext:
        privileged: true
    `, 'yaml', 'config');
    const findings = scanFileForPatterns(file);
    const found = findings.find(f => f.ruleId === 'k8s.privileged-container');
    assert.ok(found, 'Should detect privileged container');
    assert.equal(found!.severity, 'critical');
  });

  test('detects hostNetwork: true', () => {
    const file = makeFile('pod.yaml', `
      spec:
        hostNetwork: true
    `, 'yaml', 'config');
    const findings = scanFileForPatterns(file);
    const found = findings.find(f => f.ruleId === 'k8s.host-network');
    assert.ok(found, 'Should detect hostNetwork: true');
    assert.equal(found!.severity, 'high');
  });

  test('detects hostPID: true', () => {
    const file = makeFile('pod.yaml', `
      spec:
        hostPID: true
    `, 'yaml', 'config');
    const findings = scanFileForPatterns(file);
    const found = findings.find(f => f.ruleId === 'k8s.host-pid');
    assert.ok(found, 'Should detect hostPID: true');
  });

  test('detects runAsUser: 0', () => {
    const file = makeFile('deployment.yaml', `
        securityContext:
          runAsUser: 0
    `, 'yaml', 'config');
    const findings = scanFileForPatterns(file);
    const found = findings.find(f => f.ruleId === 'k8s.run-as-root');
    assert.ok(found, 'Should detect runAsUser: 0');
  });

  test('detects allowPrivilegeEscalation: true', () => {
    const file = makeFile('pod.yaml', `
        securityContext:
          allowPrivilegeEscalation: true
    `, 'yaml', 'config');
    const findings = scanFileForPatterns(file);
    const found = findings.find(f => f.ruleId === 'k8s.allow-privilege-escalation');
    assert.ok(found, 'Should detect allowPrivilegeEscalation: true');
  });
});

// ─── Terraform ────────────────────────────────────────────────────────────────

describe('multilang-engine — Terraform', () => {
  test('detects public-read S3 ACL', () => {
    const file = makeFile('main.tf', `
resource "aws_s3_bucket_acl" "example" {
  acl = "public-read"
}
    `, 'terraform', 'infrastructure');
    const findings = scanFileForPatterns(file);
    const found = findings.find(f => f.ruleId === 'terraform.public-s3');
    assert.ok(found, 'Should detect public-read S3 ACL');
    assert.equal(found!.severity, 'high');
  });
});

// ─── Python ──────────────────────────────────────────────────────────────────

describe('multilang-engine — Python', () => {
  test('detects eval() in Python', () => {
    const file = makeFile('app.py', `
result = eval(user_input)
    `, 'python');
    const findings = scanFileForPatterns(file);
    const found = findings.find(f => f.ruleId === 'python.eval-exec');
    assert.ok(found, 'Should detect Python eval()');
  });

  test('detects subprocess shell=True', () => {
    const file = makeFile('utils.py', `
subprocess.run(cmd, shell=True)
    `, 'python');
    const findings = scanFileForPatterns(file);
    const found = findings.find(f => f.ruleId === 'python.subprocess-shell');
    assert.ok(found, 'Should detect subprocess shell=True');
    assert.equal(found!.severity, 'high');
  });

  test('detects pickle.loads()', () => {
    const file = makeFile('serializer.py', `
data = pickle.loads(raw_bytes)
    `, 'python');
    const findings = scanFileForPatterns(file);
    const found = findings.find(f => f.ruleId === 'python.pickle-loads');
    assert.ok(found, 'Should detect pickle.loads()');
  });

  test('no finding for # commented eval', () => {
    const file = makeFile('app.py', `
# result = eval(dangerous)
    `, 'python');
    const findings = scanFileForPatterns(file);
    const found = findings.find(f => f.ruleId === 'python.eval-exec');
    assert.equal(found, undefined, 'Should not flag commented-out eval');
  });
});

// ─── PHP ─────────────────────────────────────────────────────────────────────

describe('multilang-engine — PHP', () => {
  test('detects eval() in PHP', () => {
    const file = makeFile('page.php', `
<?php eval($user_code); ?>
    `, 'php');
    const findings = scanFileForPatterns(file);
    const found = findings.find(f => f.ruleId === 'php.eval');
    assert.ok(found, 'Should detect PHP eval()');
  });

  test('detects shell_exec in PHP', () => {
    const file = makeFile('cmd.php', `
<?php $output = shell_exec($cmd); ?>
    `, 'php');
    const findings = scanFileForPatterns(file);
    const found = findings.find(f => f.ruleId === 'php.shell-exec');
    assert.ok(found, 'Should detect shell_exec');
  });

  test('detects unserialize in PHP', () => {
    const file = makeFile('data.php', `
$obj = unserialize($_POST['data']);
    `, 'php');
    const findings = scanFileForPatterns(file);
    const found = findings.find(f => f.ruleId === 'php.unserialize');
    assert.ok(found, 'Should detect unserialize');
  });
});

// ─── CI/CD ────────────────────────────────────────────────────────────────────

describe('multilang-engine — CI/CD', () => {
  test('detects curl|bash in GitHub Actions', () => {
    const file = makeFile('.github/workflows/ci.yml', `
      - name: Install
        run: curl -fsSL https://example.com/install.sh | bash
    `, 'yaml', 'ci_cd');
    const findings = scanFileForPatterns(file);
    const found = findings.find(f => f.ruleId === 'cicd.curl-pipe-bash');
    assert.ok(found, 'Should detect curl|bash in CI pipeline');
  });

  test('no findings from non-CI yaml with same content', () => {
    const file = makeFile('values.yaml', `
      run: curl -fsSL https://example.com/install.sh | bash
    `, 'yaml', 'config');
    const findings = scanFileForPatterns(file);
    const found = findings.find(f => f.ruleId === 'cicd.curl-pipe-bash');
    assert.equal(found, undefined, 'cicd rules should not fire on non-ci_cd yaml');
  });

  test('no findings for unsupported language', () => {
    const file = makeFile('app.ts', `
      eval("dangerous")
    `, 'typescript', 'source');
    // Python/PHP eval rules should not match TypeScript files
    const findings = scanFileForPatterns(file);
    const phpEval = findings.find(f => f.ruleId === 'php.eval');
    const pyEval = findings.find(f => f.ruleId === 'python.eval-exec');
    assert.equal(phpEval, undefined, 'PHP eval should not fire on TypeScript');
    assert.equal(pyEval, undefined, 'Python eval should not fire on TypeScript');
  });
});
