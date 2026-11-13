-- Banco do bolão (Supabase). A senha do organizador é definida à parte:
--   insert into public.bolao_config (chave, valor) values ('senha', 'SUA_SENHA');

create table if not exists public.bolao_palpites (
  id bigint generated always as identity primary key,
  nome text not null unique check (nome in ('Andressa','Bruno','Cadu','Iris','Luciana')),
  palpites jsonb not null check (jsonb_typeof(palpites) = 'object'),
  criado_em timestamptz not null default now()
);
alter table public.bolao_palpites enable row level security;

create table if not exists public.bolao_config (
  chave text primary key,
  valor text not null
);
alter table public.bolao_config enable row level security;

-- Qualquer um pode enviar o próprio palpite, mas ninguém lê a tabela diretamente.
revoke all on public.bolao_palpites from anon, authenticated;
grant insert (nome, palpites) on public.bolao_palpites to anon;
drop policy if exists "bolao enviar palpite" on public.bolao_palpites;
create policy "bolao enviar palpite" on public.bolao_palpites for insert to anon with check (true);
revoke all on public.bolao_config from anon, authenticated;

-- Lista pública de quem já respondeu (sem os palpites).
create or replace function public.bolao_quem_respondeu()
returns table (nome text, criado_em timestamptz)
language sql security definer set search_path = public stable as $$
  select nome, criado_em from public.bolao_palpites order by criado_em;
$$;

-- Palpites completos, só com a senha do organizador.
create or replace function public.bolao_revelar(senha text)
returns table (nome text, palpites jsonb, criado_em timestamptz)
language plpgsql security definer set search_path = public stable as $$
begin
  if not exists (select 1 from public.bolao_config c where c.chave = 'senha' and c.valor = bolao_revelar.senha) then
    raise exception 'senha incorreta';
  end if;
  return query select p.nome, p.palpites, p.criado_em from public.bolao_palpites p order by p.criado_em;
end;
$$;

revoke all on function public.bolao_quem_respondeu() from public;
revoke all on function public.bolao_revelar(text) from public;
grant execute on function public.bolao_quem_respondeu() to anon;
grant execute on function public.bolao_revelar(text) to anon;
