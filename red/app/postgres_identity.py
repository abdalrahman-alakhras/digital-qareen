"""Fail-closed PostgreSQL identity boundary for service connection pools."""

class DatabaseIdentityError(RuntimeError):
    pass


_CONFIG = {
    'gateway': ('dq_gateway_login', 'app_gateway'),
    'worker': ('dq_worker_login', 'app_worker'),
}

_LOGIN_SQL = """
SELECT session_user::text AS login, current_user::text AS active,
       r.rolcanlogin AS can_login, r.rolsuper AS superuser,
       r.rolbypassrls AS bypass_rls, r.rolcreaterole AS create_role,
       r.rolcreatedb AS create_db, r.rolreplication AS replication,
       r.rolinherit AS inherits,
       pg_has_role(session_user, $1::name, 'SET') AS can_set_target
FROM pg_catalog.pg_roles AS r
WHERE r.rolname = session_user
"""

_ACTIVE_SQL = """
SELECT session_user::text AS login, current_user::text AS active,
       r.rolcanlogin AS can_login, r.rolsuper AS superuser,
       r.rolbypassrls AS bypass_rls
FROM pg_catalog.pg_roles AS r
WHERE r.rolname = current_user
"""

_GATEWAY_SQL = """
SELECT has_table_privilege(current_user,'public.gateway_operations','UPDATE') AS operations_update,
       has_table_privilege(current_user,'public.cumulative_budget_reservations','UPDATE') AS reservations_update,
       has_table_privilege(current_user,'public.idempotency_registry','UPDATE') AS idempotency_update,
       has_table_privilege(current_user,'public.budget_reconciliation_audit','INSERT') AS audit_insert
"""

_WORKER_SQL = """
SELECT has_function_privilege(current_user,
       'public.finalize_outbox_event_v2(uuid,uuid,text,text,text)',
       'EXECUTE') AS forbidden_finalize
"""


async def enforce_service_identity(conn, service: str) -> None:
    if service not in _CONFIG:
        raise DatabaseIdentityError('Unrecognized PostgreSQL service')
    login, target = _CONFIG[service]
    # asyncpg's default pool reset does not explicitly issue RESET ROLE.
    # Never trust role state inherited from an earlier checkout.
    await conn.execute('RESET ROLE')
    before = await conn.fetchrow(_LOGIN_SQL, target)
    if (before is None or before['login'] != login
            or before['active'] != login or before['can_login'] is not True
            or before['superuser'] is not False or before['bypass_rls'] is not False
            or before['create_role'] is not False or before['create_db'] is not False
            or before['replication'] is not False or before['inherits'] is not False
            or before['can_set_target'] is not True):
        raise DatabaseIdentityError(f'Unsafe {service} PostgreSQL login identity')

    # Target role is from an internal closed mapping, never from a DSN.
    await conn.execute('SET ROLE ' + target)
    after = await conn.fetchrow(_ACTIVE_SQL)
    if (after is None or after['login'] != login or after['active'] != target
            or after['can_login'] is not False
            or after['superuser'] is not False or after['bypass_rls'] is not False):
        raise DatabaseIdentityError(f'Unsafe {service} PostgreSQL active role')

    if service == 'gateway':
        rights = await conn.fetchrow(_GATEWAY_SQL)
        if rights is None or any(rights[x] is not False for x in (
            'operations_update', 'reservations_update', 'idempotency_update',
            'audit_insert'
        )):
            raise DatabaseIdentityError('Gateway direct financial write authority detected')
    else:
        rights = await conn.fetchrow(_WORKER_SQL)
        if rights is None or rights['forbidden_finalize'] is not False:
            raise DatabaseIdentityError('Worker unsafe finalizer authority detected')


async def gateway_connection_setup(conn) -> None:
    await enforce_service_identity(conn, 'gateway')


async def worker_connection_setup(conn) -> None:
    await enforce_service_identity(conn, 'worker')
