import type { DetectedStack, ScannedFile } from '@cybermat/shared';

export function detectStack(files: ScannedFile[], packageJson?: Record<string, unknown>): DetectedStack {
  const stack: DetectedStack = {
    languages: [],
    frameworks: [],
    packageManagers: [],
    authProviders: [],
    databases: [],
    deploymentTargets: [],
    aiProviders: [],
  };

  const allDeps = getAllDependencies(packageJson);
  const hasFile = (name: string) => files.some(f => f.relativePath === name || f.relativePath.endsWith('/' + name));
  const hasDir = (prefix: string) => files.some(f => f.relativePath.startsWith(prefix));

  // Languages
  if (files.some(f => f.extension === '.ts' || f.extension === '.tsx')) stack.languages.push('TypeScript');
  if (files.some(f => f.extension === '.js' || f.extension === '.jsx')) stack.languages.push('JavaScript');

  // Frameworks
  if (hasDep(allDeps, 'next')) stack.frameworks.push('Next.js');
  else if (hasDep(allDeps, 'react')) stack.frameworks.push('React');
  if (hasDep(allDeps, 'vite')) stack.frameworks.push('Vite');
  if (hasDep(allDeps, 'express')) stack.frameworks.push('Express');
  if (hasDep(allDeps, 'fastify')) stack.frameworks.push('Fastify');
  if (hasDep(allDeps, '@nestjs/core')) stack.frameworks.push('NestJS');
  if (hasDep(allDeps, 'svelte') || hasDep(allDeps, '@sveltejs/kit')) stack.frameworks.push('SvelteKit');
  if (hasDep(allDeps, 'astro')) stack.frameworks.push('Astro');
  if (hasDep(allDeps, 'nuxt') || hasDep(allDeps, 'nuxt3')) stack.frameworks.push('Nuxt');

  // Auth providers
  if (hasDep(allDeps, '@clerk/nextjs') || hasDep(allDeps, '@clerk/clerk-react') || hasDep(allDeps, '@clerk/backend')) {
    stack.authProviders.push('Clerk');
  }
  if (hasDep(allDeps, 'next-auth') || hasDep(allDeps, '@auth/core') || hasDep(allDeps, '@auth/nextjs')) {
    stack.authProviders.push('NextAuth / Auth.js');
  }
  if (hasDep(allDeps, 'better-auth')) stack.authProviders.push('Better Auth');
  if (hasDep(allDeps, '@supabase/supabase-js') || hasDep(allDeps, '@supabase/auth-helpers-nextjs')) {
    if (!stack.authProviders.includes('Supabase Auth')) stack.authProviders.push('Supabase Auth');
  }
  if (hasDep(allDeps, 'firebase') || hasDep(allDeps, 'firebase-admin')) {
    if (!stack.authProviders.includes('Firebase Auth')) stack.authProviders.push('Firebase Auth');
  }

  // Databases
  if (hasDep(allDeps, '@prisma/client') || hasDep(allDeps, 'prisma')) stack.databases.push('Prisma');
  if (hasDep(allDeps, 'drizzle-orm')) stack.databases.push('Drizzle');
  if (hasDep(allDeps, '@supabase/supabase-js')) stack.databases.push('Supabase');
  if (hasDep(allDeps, 'firebase') || hasDep(allDeps, 'firebase-admin')) stack.databases.push('Firebase');
  if (hasDep(allDeps, 'mongodb') || hasDep(allDeps, 'mongoose')) stack.databases.push('MongoDB');
  if (hasDep(allDeps, 'pg') || hasDep(allDeps, 'postgres') || hasDep(allDeps, 'pg-promise')) stack.databases.push('PostgreSQL');
  if (hasDep(allDeps, 'redis') || hasDep(allDeps, 'ioredis') || hasDep(allDeps, '@upstash/redis')) stack.databases.push('Redis');

  // Deployment
  if (hasFile('vercel.json') || hasDep(allDeps, 'vercel') || hasDir('.vercel')) stack.deploymentTargets.push('Vercel');
  if (hasFile('netlify.toml')) stack.deploymentTargets.push('Netlify');
  if (hasFile('Dockerfile') || hasFile('docker-compose.yml') || hasFile('docker-compose.yaml')) {
    stack.deploymentTargets.push('Docker');
  }
  if (hasDir('.github/workflows')) stack.deploymentTargets.push('GitHub Actions');

  // AI providers
  if (hasDep(allDeps, 'openai')) stack.aiProviders.push('OpenAI');
  if (hasDep(allDeps, '@anthropic-ai/sdk')) stack.aiProviders.push('Anthropic');
  if (hasDep(allDeps, '@google/generative-ai') || hasDep(allDeps, '@google-ai/generativelanguage')) stack.aiProviders.push('Google AI');
  if (hasDep(allDeps, 'groq-sdk')) stack.aiProviders.push('Groq');
  if (hasDep(allDeps, 'mistral-api') || hasDep(allDeps, '@mistralai/mistralai')) stack.aiProviders.push('Mistral');
  if (hasDep(allDeps, 'replicate')) stack.aiProviders.push('Replicate');
  if (hasDep(allDeps, 'together-ai') || hasDep(allDeps, 'together')) stack.aiProviders.push('Together AI');
  if (hasDep(allDeps, 'ai') || hasDep(allDeps, '@ai-sdk/core')) stack.aiProviders.push('Vercel AI SDK');

  // Package managers
  if (hasFile('pnpm-lock.yaml')) stack.packageManagers.push('pnpm');
  else if (hasFile('yarn.lock')) stack.packageManagers.push('yarn');
  else if (hasFile('bun.lockb') || hasFile('bun.lock')) stack.packageManagers.push('bun');
  else if (hasFile('package-lock.json')) stack.packageManagers.push('npm');

  return stack;
}

function getAllDependencies(packageJson?: Record<string, unknown>): string[] {
  if (!packageJson) return [];
  const deps = Object.keys((packageJson.dependencies as Record<string, string>) || {});
  const devDeps = Object.keys((packageJson.devDependencies as Record<string, string>) || {});
  const peerDeps = Object.keys((packageJson.peerDependencies as Record<string, string>) || {});
  return [...deps, ...devDeps, ...peerDeps];
}

function hasDep(deps: string[], name: string): boolean {
  return deps.some(d => d === name || d.startsWith(name + '/'));
}
