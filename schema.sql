-- Run this whole file in Supabase > SQL Editor.
create table profiles(
  id uuid primary key references auth.users on delete cascade,
  full_name text,
  role text not null default 'scholar' check (role in ('admin','staff','scholar')));

create table scholarship_programs(
  id bigint generated always as identity primary key,
  program_name text not null unique,
  required_gwa numeric(3,2) not null check (required_gwa between 1 and 5), -- MAXIMUM allowed GWA (1.0 best, 5.0 fail)
  min_units int not null check (min_units >= 0),
  allow_failing_grade boolean not null default false,
  active boolean not null default true);

create table scholars(
  id bigint generated always as identity primary key,
  student_id text not null unique check (length(trim(student_id)) > 0),
  full_name text not null,
  degree_program text not null,
  year_level int not null check (year_level between 1 and 6),
  scholarship_id bigint not null references scholarship_programs(id),
  status text not null default 'Active' check (status in ('Active','Pending Submission','For Verification','Compliant','With Deficiency','Probationary','For Renewal','Renewed','Disqualified')));

create table grade_submissions(
  id bigint generated always as identity primary key,
  scholar_id bigint not null references scholars(id),
  academic_year text not null,
  semester text not null check (semester in ('1st','2nd','Summer')),
  gwa numeric(3,2) not null check (gwa between 1 and 5),
  units_enrolled int not null check (units_enrolled >= 0),
  failed_subjects int not null default 0 check (failed_subjects >= 0),
  incomplete_subjects int not null default 0 check (incomplete_subjects >= 0),
  submission_status text not null default 'Pending' check (submission_status in ('Pending','Verified','Returned')),
  submitted_at timestamptz not null default now(),
  verified_by uuid references auth.users(id),
  verified_at timestamptz,
  evaluation_result text check (evaluation_result in ('Compliant','With Deficiency')),
  deficiency_notes text);

-- BR-03/BR-12: one submission per scholar/year/semester (a Returned one may be resubmitted)
create unique index one_submission_per_term on grade_submissions(scholar_id, academic_year, semester) where submission_status <> 'Returned';

-- BR-08/BR-09: verified records cannot be changed
create function lock_verified() returns trigger language plpgsql as $$
begin
  if old.submission_status = 'Verified' then raise exception 'Verified submissions cannot be changed'; end if;
  return new;
end $$;
create trigger trg_lock_verified before update on grade_submissions for each row execute function lock_verified();

-- profile is created automatically for every new auth user (default role: scholar)
create function handle_new_user() returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into profiles(id, full_name) values (new.id, coalesce(new.raw_user_meta_data->>'full_name', new.email));
  return new;
end $$;
create trigger on_auth_user_created after insert on auth.users for each row execute function handle_new_user();

create function is_staff() returns boolean language sql security definer set search_path = public stable as $$
  select exists (select 1 from profiles where id = auth.uid() and role in ('admin','staff')) $$;

-- BR-04/BR-05: verification + compliance evaluation done in one authorized, server-side step
create function verify_submission(p_id bigint) returns text language plpgsql security definer set search_path = public as $$
declare s grade_submissions; p scholarship_programs; notes text := ''; res text;
begin
  if not is_staff() then raise exception 'Only staff or admin may verify submissions'; end if;
  select * into s from grade_submissions where id = p_id for update;
  if not found then raise exception 'Submission not found'; end if;
  if s.submission_status <> 'Pending' then raise exception 'Only Pending submissions can be verified'; end if;
  select sp.* into p from scholarship_programs sp join scholars sc on sc.scholarship_id = sp.id where sc.id = s.scholar_id;
  if s.gwa > p.required_gwa then notes := notes || format('GWA %s is worse than required %s. ', s.gwa, p.required_gwa); end if;
  if s.units_enrolled < p.min_units then notes := notes || format('Units %s below minimum %s. ', s.units_enrolled, p.min_units); end if;
  if s.failed_subjects > 0 and not p.allow_failing_grade then notes := notes || format('%s failed subject(s) not allowed. ', s.failed_subjects); end if;
  res := case when notes = '' then 'Compliant' else 'With Deficiency' end;
  update grade_submissions set submission_status = 'Verified', verified_by = auth.uid(), verified_at = now(),
    evaluation_result = res, deficiency_notes = nullif(trim(notes), '') where id = p_id;
  update scholars set status = res where id = s.scholar_id;
  return res;
end $$;

alter table profiles enable row level security;
alter table scholarship_programs enable row level security;
alter table scholars enable row level security;
alter table grade_submissions enable row level security;
create policy "own profile" on profiles for select using (id = auth.uid());
create policy "staff programs" on scholarship_programs for all using (is_staff()) with check (is_staff());
create policy "staff scholars" on scholars for all using (is_staff()) with check (is_staff());
create policy "staff submissions" on grade_submissions for all using (is_staff()) with check (is_staff());

-- Sample programs (illustrative rules only; replace with your institution's policies)
insert into scholarship_programs(program_name, required_gwa, min_units, allow_failing_grade) values
 ('University Academic Scholar', 1.75, 18, false),
 ('Government Scholarship (Sample)', 2.50, 15, false),
 ('Private Grant (Sample)', 3.00, 12, true);

-- After creating your user (Authentication > Users > Add user), make it staff/admin:
-- update profiles set role = 'admin' where id = (select id from auth.users where email = 'you@example.com');

-- ===== ROLES (admin / staff / scholar) =====
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
