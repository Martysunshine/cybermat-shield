'use client';
// VULNERABLE EXAMPLE — Supabase service role key used in a client file
// Scanner should flag: service role key in client = critical
// FAKE key for scanner testing only — not a real credential

import { createClient } from '@supabase/supabase-js';

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL!;

// VULNERABLE: Using the service role key in a client file bypasses ALL RLS policies.
// The service role key grants full database access to anyone who loads this JS file.
// FAKE key below — scanner should still detect the pattern
const SUPABASE_SERVICE_ROLE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InRlc3QiLCJyb2xlIjoic2VydmljZV9yb2xlIn0.FAKE_SERVICE_ROLE_FOR_TESTING';

// VULNERABLE: Service role client exported from a 'use client' file
export const supabaseAdmin = createClient(supabaseUrl, SUPABASE_SERVICE_ROLE_KEY);

// Should be: use anon key on client, service role only in server-side files
export const supabaseAnonClient = createClient(
  supabaseUrl,
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
);
