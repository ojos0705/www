-- Add shared landing-page authentication support to the existing KUHP project.
-- Run this once in the KUHP Supabase project's SQL Editor.

alter table public.profiles
    add column if not exists role text not null default 'user';

alter table public.profiles enable row level security;

drop policy if exists "Landing users can read own profile" on public.profiles;
create policy "Landing users can read own profile"
    on public.profiles
    for select
    to authenticated
    using ((select auth.uid()) = id);

drop policy if exists "Landing users can update own profile" on public.profiles;
create policy "Landing users can update own profile"
    on public.profiles
    for update
    to authenticated
    using ((select auth.uid()) = id)
    with check ((select auth.uid()) = id);

grant select on public.profiles to authenticated;
grant update (full_name) on public.profiles to authenticated;

create or replace function public.prevent_profile_role_self_change()
returns trigger
language plpgsql
set search_path = public, pg_temp
as $$
begin
    if auth.role() in ('anon', 'authenticated') then
        if tg_op = 'INSERT' then
            new.role := 'user';
        elsif new.role is distinct from old.role then
            raise exception 'Profile role cannot be changed by the account owner.'
                using errcode = '42501';
        end if;
    end if;

    return new;
end;
$$;

drop trigger if exists prevent_profile_role_self_change on public.profiles;
create trigger prevent_profile_role_self_change
    before insert or update on public.profiles
    for each row execute function public.prevent_profile_role_self_change();

create or replace function public.create_profile_for_landing_user()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
    insert into public.profiles (id, full_name)
    values (
        new.id,
        coalesce(new.raw_user_meta_data ->> 'full_name', '')
    )
    on conflict (id) do nothing;

    return new;
end;
$$;

drop trigger if exists on_landing_auth_user_created on auth.users;
create trigger on_landing_auth_user_created
    after insert on auth.users
    for each row execute function public.create_profile_for_landing_user();

create or replace function public.get_landing_admin_user_count()
returns bigint
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
    if not exists (
        select 1
        from public.profiles
        where id = (select auth.uid())
          and role = 'admin'
    ) then
        raise exception 'Admin access required.' using errcode = '42501';
    end if;

    return (select count(*) from public.profiles);
end;
$$;

revoke all on function public.get_landing_admin_user_count() from public, anon;
grant execute on function public.get_landing_admin_user_count() to authenticated;
