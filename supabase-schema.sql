-- ════════════════════════════════════════════════════
-- CheckVibe — Supabase schema migration
-- Run this once in Supabase → SQL Editor → New query → Run.
-- ════════════════════════════════════════════════════

-- 1. The scans table. result_json stores the FULL /api/scan response,
--    so the report detail page renders with zero format conversion.
create table if not exists public.scans (
  id            uuid primary key default gen_random_uuid(),
  user_id       uuid references auth.users(id) on delete cascade not null,
  url           text  not null,
  score         int   not null,
  total_checks  int   not null,
  passed_checks int   not null,
  failed_checks int   not null,
  sev_critical  int   default 0,
  sev_high      int   default 0,
  sev_medium    int   default 0,
  sev_low       int   default 0,
  response_time int,
  status_code   int,
  result_json   jsonb not null,
  created_at    timestamptz default now()
);

-- Fast lookup of a user's scans, newest first.
create index if not exists scans_user_created_idx
  on public.scans (user_id, created_at desc);

-- 2. Row Level Security: a user can only ever touch their own rows.
--    This is the real security boundary — the anon key being public is fine
--    because the database itself enforces ownership.
alter table public.scans enable row level security;

drop policy if exists "scans_select_own" on public.scans;
create policy "scans_select_own" on public.scans
  for select using (auth.uid() = user_id);

drop policy if exists "scans_insert_own" on public.scans;
create policy "scans_insert_own" on public.scans
  for insert with check (auth.uid() = user_id);

drop policy if exists "scans_delete_own" on public.scans;
create policy "scans_delete_own" on public.scans
  for delete using (auth.uid() = user_id);

-- Done. The frontend @supabase/supabase-js SDK reads/writes this table;
-- RLS guarantees users never see another user's scans.
