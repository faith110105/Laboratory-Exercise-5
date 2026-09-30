-- ROLES UPDATE: run once in Supabase > SQL Editor (safe to re-run). Adds admin / staff / scholar behaviour.
alter table profiles add column if not exists email text;
alter table scholars add column if not exists email text;
create unique index if not exists scholars_email_uq on scholars(lower(email));
insert into profiles(id, full_name, email) select id, email, email from auth.users on conflict (id) do nothing;
update profiles p set email = u.email from auth.users u where u.id = p.id;

create or replace function handle_new_user() returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into profiles(id, full_name, email) values (new.id, coalesce(new.raw_user_meta_data->>'full_name', new.email), new.email);
  return new;
end $$;

create or replace function is_admin() returns boolean language sql security definer set search_path = public stable as $$
  select exists (select 1 from profiles where id = auth.uid() and role = 'admin') $$;

-- links a scholar login to a scholar record by matching email
create or replace function my_scholar_id() returns bigint language sql security definer set search_path = public stable as $$
  select s.id from scholars s join profiles p on lower(p.email) = lower(s.email) where p.id = auth.uid() limit 1 $$;

-- new submission (from anyone) puts the scholar in "For Verification"
create or replace function mark_for_verification() returns trigger language plpgsql security definer set search_path = public as $$
begin update scholars set status = 'For Verification' where id = new.scholar_id; return new; end $$;
drop trigger if exists trg_mark_fv on grade_submissions;
create trigger trg_mark_fv after insert on grade_submissions for each row execute function mark_for_verification();

-- profiles: everyone reads own; admin reads/changes all
drop policy if exists "own profile" on profiles;
drop policy if exists "profile read" on profiles;
drop policy if exists "admin manage profiles" on profiles;
create policy "profile read" on profiles for select using (id = auth.uid() or is_admin());
create policy "admin manage profiles" on profiles for update using (is_admin()) with check (is_admin());

-- programs: all logged-in users can read; only admin can change
drop policy if exists "staff programs" on scholarship_programs;
drop policy if exists "programs read" on scholarship_programs;
drop policy if exists "programs admin write" on scholarship_programs;
create policy "programs read" on scholarship_programs for select using (auth.uid() is not null);
create policy "programs admin write" on scholarship_programs for all using (is_admin()) with check (is_admin());

-- scholars: staff/admin full access; a scholar sees only their own record
drop policy if exists "scholar own" on scholars;
create policy "scholar own" on scholars for select using (id = my_scholar_id());

-- submissions: staff/admin full access; a scholar reads own and may add own Pending submission only
drop policy if exists "scholar own read" on grade_submissions;
drop policy if exists "scholar own insert" on grade_submissions;
create policy "scholar own read" on grade_submissions for select using (scholar_id = my_scholar_id());
create policy "scholar own insert" on grade_submissions for insert
  with check (scholar_id = my_scholar_id() and submission_status = 'Pending' and verified_by is null and evaluation_result is null);

-- Make yourself admin (change the email). Then manage other users' roles from the app's Users page.
-- update profiles set role = 'admin' where email = 'staff@lab4.test';
