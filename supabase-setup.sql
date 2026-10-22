-- 마음 한스푼: multi-page shared birthday funding schema
create extension if not exists pgcrypto;

create table if not exists public.mhs_pages (
  id uuid primary key default gen_random_uuid(),
  slug text not null unique check (slug ~ '^[a-z0-9][a-z0-9-]{2,39}$'),
  owner_id uuid not null references auth.users(id) on delete cascade,
  settings jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists mhs_pages_owner_idx on public.mhs_pages(owner_id);

create table if not exists public.mhs_messages (
  id uuid primary key default gen_random_uuid(),
  page_id uuid not null references public.mhs_pages(id) on delete cascade,
  name text not null check (char_length(btrim(name)) between 2 and 24),
  message text not null check (char_length(btrim(message)) between 5 and 180),
  is_hidden boolean not null default false,
  created_at timestamptz not null default now()
);
alter table public.mhs_messages add column if not exists is_hidden boolean not null default false;
create index if not exists mhs_messages_page_date_idx on public.mhs_messages(page_id, created_at desc);
create unique index if not exists mhs_messages_duplicate_idx on public.mhs_messages
  (page_id, lower(regexp_replace(btrim(name), '\s+', ' ', 'g')), lower(regexp_replace(btrim(message), '\s+', ' ', 'g')));

create table if not exists public.mhs_donations (
  id uuid primary key default gen_random_uuid(),
  page_id uuid not null references public.mhs_pages(id) on delete cascade,
  gift_index integer not null default 0 check (gift_index >= 0),
  amount bigint not null check (amount > 0),
  donor_alias text,
  created_at timestamptz not null default now()
);
alter table public.mhs_donations add column if not exists donor_alias text;
create index if not exists mhs_donations_page_idx on public.mhs_donations(page_id, created_at desc);
create unique index if not exists mhs_donations_page_alias_uidx on public.mhs_donations(page_id, donor_alias) where donor_alias is not null;
with ranked as (
  select id, page_id, row_number() over (partition by page_id order by created_at, id) as rn
  from public.mhs_donations
  where donor_alias is null
), words as (
  select array[
    '별사탕','솜사탕','오로라','고양이','달토끼','구름','민들레','반짝이','초코송이','복숭아',
    '달빛','무지개','유자차','푸딩','벚꽃','은하수','아기곰','별빛','눈꽃','바다',
    '라벤더','마카롱','모찌','햇살','달콤이','반달','초승달','작은별','솜구름','산들바람',
    '해바라기','수국','튤립','진주','보름달','별가루','레몬','체리','토끼풀','코스모스',
    '밀크티','달고나','자몽','나비','청포도','밤하늘','눈송이','고래','도토리','강아지',
    '달무리','별조각','장미','라일락','캔디','바닐라','아이스크림','비눗방울','조약돌','하늘'
  ]::text[] as list
)
update public.mhs_donations d
set donor_alias = case
  when r.rn <= cardinality(w.list) then w.list[r.rn::int]
  else w.list[((r.rn - 1) % cardinality(w.list) + 1)::int] || ceil(r.rn::numeric / cardinality(w.list))::int::text
end
from ranked r cross join words w
where d.id = r.id;

create table if not exists public.mhs_donation_private (
  id uuid primary key references public.mhs_donations(id) on delete cascade,
  donor_name text not null default '' check (char_length(donor_name) <= 30)
);

create table if not exists public.mhs_message_limits (
  visitor_key uuid primary key,
  last_sent_at timestamptz not null default now()
);

alter table public.mhs_pages enable row level security;
alter table public.mhs_messages enable row level security;
alter table public.mhs_donations enable row level security;
alter table public.mhs_donation_private enable row level security;
revoke all on public.mhs_pages, public.mhs_messages, public.mhs_donations, public.mhs_donation_private from anon, authenticated;
grant select on public.mhs_pages to anon, authenticated;
grant insert, update, delete on public.mhs_pages to authenticated;
grant select on public.mhs_messages to anon, authenticated;
grant update, delete on public.mhs_messages to authenticated;
grant select, insert, update, delete on public.mhs_donations to authenticated;
grant select on public.mhs_donations to anon;
grant select, insert, delete on public.mhs_donation_private to authenticated;

drop policy if exists "public can read pages" on public.mhs_pages;
create policy "public can read pages" on public.mhs_pages for select to anon, authenticated using (true);
drop policy if exists "owner creates own page" on public.mhs_pages;
create policy "owner creates own page" on public.mhs_pages for insert to authenticated with check ((select auth.uid()) = owner_id);
drop policy if exists "owner updates own page" on public.mhs_pages;
create policy "owner updates own page" on public.mhs_pages for update to authenticated using ((select auth.uid()) = owner_id) with check ((select auth.uid()) = owner_id);
drop policy if exists "owner deletes own page" on public.mhs_pages;
create policy "owner deletes own page" on public.mhs_pages for delete to authenticated using ((select auth.uid()) = owner_id);

drop policy if exists "public can read messages" on public.mhs_messages;
create policy "public can read visible messages" on public.mhs_messages for select to anon, authenticated using (not is_hidden);
drop policy if exists "owner can read own hidden messages" on public.mhs_messages;
create policy "owner can read own hidden messages" on public.mhs_messages for select to authenticated using (
  exists (select 1 from public.mhs_pages p where p.id = page_id and p.owner_id = (select auth.uid()))
);
drop policy if exists "public can send clean messages" on public.mhs_messages;
create policy "public can send clean messages" on public.mhs_messages for insert to anon, authenticated
with check (
  char_length(btrim(name)) between 2 and 24 and char_length(btrim(message)) between 5 and 180
  and message !~* '(https?://|www\.)' and message !~ '(.)\1{9,}'
  and not exists (
    select 1 from public.mhs_messages old
    where old.page_id = mhs_messages.page_id
      and lower(regexp_replace(btrim(old.name), '\s+', ' ', 'g')) = lower(regexp_replace(btrim(mhs_messages.name), '\s+', ' ', 'g'))
      and lower(regexp_replace(btrim(old.message), '\s+', ' ', 'g')) = lower(regexp_replace(btrim(mhs_messages.message), '\s+', ' ', 'g'))
  )
);
drop policy if exists "owner deletes page messages" on public.mhs_messages;
create policy "owner deletes page messages" on public.mhs_messages for delete to authenticated using (
  exists (select 1 from public.mhs_pages p where p.id = page_id and p.owner_id = (select auth.uid()))
);
drop policy if exists "owner hides own messages" on public.mhs_messages;
create policy "owner hides own messages" on public.mhs_messages for update to authenticated
using (exists (select 1 from public.mhs_pages p where p.id = page_id and p.owner_id = (select auth.uid())))
with check (exists (select 1 from public.mhs_pages p where p.id = page_id and p.owner_id = (select auth.uid())));

alter table public.mhs_message_limits enable row level security;
revoke all on public.mhs_message_limits from anon, authenticated;
create or replace function public.submit_birthday_message(
  p_page_id uuid, p_name text, p_message text, p_visitor_key uuid, p_website text default ''
) returns uuid
language plpgsql security definer set search_path = '' as $$
declare new_id uuid;
begin
  if coalesce(p_website, '') <> '' then raise exception '스팸 요청으로 판단되어 등록하지 않았어요.'; end if;
  if char_length(btrim(p_name)) not between 2 and 24 or char_length(btrim(p_message)) not between 5 and 180 then
    raise exception '이름과 메시지 길이를 확인해 주세요.';
  end if;
  if p_message ~* '(https?://|www\.)' or p_message ~ '(.)\1{9,}' or p_message !~ '[-[:alnum:]가-힣]' then
    raise exception '링크나 반복 문자가 많은 메시지는 등록할 수 없어요.';
  end if;
  insert into public.mhs_message_limits(visitor_key, last_sent_at)
  values (p_visitor_key, now())
  on conflict (visitor_key) do update set last_sent_at = now()
    where public.mhs_message_limits.last_sent_at < now() - interval '15 seconds';
  if not found then raise exception '메시지는 15초에 한 번 남길 수 있어요.'; end if;
  insert into public.mhs_messages(page_id, name, message)
  values (p_page_id, btrim(p_name), btrim(p_message)) returning id into new_id;
  return new_id;
exception when unique_violation then
  raise exception '같은 메시지는 한 번만 남길 수 있어요.';
end;
$$;
revoke all on function public.submit_birthday_message(uuid,text,text,uuid,text) from public;
grant execute on function public.submit_birthday_message(uuid,text,text,uuid,text) to anon, authenticated;

drop policy if exists "public can read donation totals" on public.mhs_donations;
create policy "public can read donation totals" on public.mhs_donations for select to anon using (true);
drop policy if exists "owner manages own donations" on public.mhs_donations;
create policy "owner manages own donations" on public.mhs_donations for all to authenticated
using (exists (select 1 from public.mhs_pages p where p.id = page_id and p.owner_id = (select auth.uid())))
with check (exists (select 1 from public.mhs_pages p where p.id = page_id and p.owner_id = (select auth.uid())));

drop policy if exists "owner manages private donor names" on public.mhs_donation_private;
create policy "owner manages private donor names" on public.mhs_donation_private for all to authenticated
using (exists (select 1 from public.mhs_donations d join public.mhs_pages p on p.id = d.page_id where d.id = mhs_donation_private.id and p.owner_id = (select auth.uid())))
with check (exists (select 1 from public.mhs_donations d join public.mhs_pages p on p.id = d.page_id where d.id = mhs_donation_private.id and p.owner_id = (select auth.uid())));
