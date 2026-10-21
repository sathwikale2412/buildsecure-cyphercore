-- Cypher Core — server-side schema.
-- Run in the Supabase SQL editor, or:  supabase db push  (after supabase link)
--
-- Two rules matter here. Every policy is pinned to auth.uid(), so no account can read or
-- write another account's rows even with the public anon key. And every column that can
-- hold user-supplied bytes is length-checked, which is the data layer's own validation:
-- the ciphertext a caller submits cannot be arbitrarily large.

create table if not exists public.vault_settings (
  user_id        uuid primary key references auth.users (id) on delete cascade,
  salt           text not null check (char_length(salt) between 16 and 128),
  check_cipher   text not null check (char_length(check_cipher) between 16 and 1024),
  check_nonce    text not null check (char_length(check_nonce) between 8 and 64),
  created_at     timestamptz not null default now()
);

create table if not exists public.vault_items (
  id              uuid primary key default gen_random_uuid(),
  user_id         uuid not null references auth.users (id) on delete cascade,
  payload_cipher  text not null check (char_length(payload_cipher) between 1 and 24000),
  payload_nonce   text not null check (char_length(payload_nonce) between 8 and 64),
  created_at      timestamptz not null default now()
);

create index if not exists vault_items_user_created
  on public.vault_items (user_id, created_at desc);

alter table public.vault_settings enable row level security;
alter table public.vault_items    enable row level security;
-- FORCE keeps the table owner and any service-role shortcut from skipping the policies.
alter table public.vault_settings force row level security;
alter table public.vault_items    force row level security;

drop policy if exists "own vault settings" on public.vault_settings;
create policy "own vault settings" on public.vault_settings
  for all to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

drop policy if exists "own vault items" on public.vault_items;
create policy "own vault items" on public.vault_items
  for all to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- Nothing is granted to anon: the two policies above target the authenticated role only,
-- so an unauthenticated caller reads zero rows and cannot insert at all.
