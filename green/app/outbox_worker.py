import asyncio
import json
import logging
import os
import random
import re
import inspect
from typing import Any, Protocol
from dataclasses import dataclass
from uuid import UUID, uuid4
import asyncpg
import httpx
from app.postgres_identity import DatabaseIdentityError


from app.auth.provider_dispatch_gate import StrictProviderBarrierError


def _dq_has_execution_barrier_in_chain(exc):
    seen = set()
    pending = [exc]
    while pending:
        current = pending.pop()
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, StrictProviderBarrierError):
            return True
        pending.append(current.__context__)
        pending.append(current.__cause__)
    return False


def _dq_has_authority_denial_in_chain(exc):
    seen = set()
    pending = [exc]
    while pending:
        current = pending.pop()
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, DatabaseIdentityError) or getattr(current, "sqlstate", None) == "42501":
            return True
        pending.append(current.__context__)
        pending.append(current.__cause__)
    return False


logger = logging.getLogger("outbox_worker")


class AsyncOutboxAuthorizationGate(Protocol):
    async def authorize_before_dispatch(self, event: Any) -> bool:
        """Return True only after an ALLOW decision is durably committed."""
        ...


class DispatchAuthorizationError(PermissionError):
    def __init__(self, reason_code: str, *, terminal: bool = False):
        self.reason_code = reason_code
        self.terminal = terminal
        super().__init__(f"Outbox dispatch blocked: {reason_code}")


class DispatchExecutionBarrierError(DispatchAuthorizationError):
    """Fatal Worker control signal; never persist as a business denial."""



@dataclass(frozen=True)
class DispatchOutcome:
    succeeded: bool
    error_code: str | None = None
    provider_reference: str | None = None
    dispatch_attempt_count: int = 0


class OutboxWorker:
    def __init__(
        self,
        dsn: str,
        worker_id: str = "worker-1",
        *,
        provider_url: str | None = None,
        authorization_gate: AsyncOutboxAuthorizationGate | None = None,
        max_attempts: int = 5,
        lease_seconds: float = 30.0,
        request_timeout: float = 3.0,
        shutdown_timeout: float = 10.0,
        poll_interval: float = 0.25,
        base_backoff_seconds: float = 1.0,
        max_backoff_seconds: float = 60.0,
    ):
        self.dsn = dsn
        self.worker_id = worker_id
        self.provider_url = (provider_url or os.getenv("MOCK_PROVIDER_URL", "http://mock-provider:8090")).rstrip("/")
        self.authorization_gate = authorization_gate
        self.max_attempts = max_attempts
        self.lease_seconds = lease_seconds
        self.request_timeout = request_timeout
        self.shutdown_timeout = shutdown_timeout
        self.poll_interval = poll_interval
        self.base_backoff_seconds = base_backoff_seconds
        self.max_backoff_seconds = max_backoff_seconds
        self.pool = None
        self.running = False
        self._bg_task = None
        self._fatal_error = None
        self._lifecycle_lock = asyncio.Lock()
        self._close_task = None
        self._has_started = False

    async def start(self):
        async with self._lifecycle_lock:
            if self._bg_task is not None and self._bg_task.done():
                self._observe_bg_task(self._bg_task)
            if self._fatal_error is not None:
                raise RuntimeError("WORKER_FATAL_RESTART_FORBIDDEN") from self._fatal_error
            if self._bg_task is not None or self.pool is not None:
                raise RuntimeError("WORKER_ALREADY_STARTED_OR_CLEANUP_PENDING")
            if self.authorization_gate is None:
                raise RuntimeError("Outbox worker startup blocked: authorization gate is not configured.")
            if not callable(getattr(self.authorization_gate, 'authorize_before_dispatch', None)):
                raise RuntimeError("Outbox worker startup blocked: authorization gate contract is invalid.")
            from app.postgres_identity import worker_connection_setup
            self.pool = await asyncpg.create_pool(dsn=self.dsn, min_size=1, max_size=5, setup=worker_connection_setup)
            self.running = True
            logger.info(f"Outbox worker [{self.worker_id}] initialized successfully.")
            self._bg_task = asyncio.create_task(self._process_loop())
            self._bg_task.add_done_callback(self._observe_bg_task)
            self._has_started = True

    def _observe_bg_task(self, task):
        if not task.done():
            return
        error = None if task.cancelled() else task.exception()
        if task is not self._bg_task:
            return
        if error is None and self.running:
            error = RuntimeError("UNEXPECTED_WORKER_TASK_EXIT")
        self.running = False
        if error is not None and self._fatal_error is None:
            self._fatal_error = error

    async def wait_until_stopped(self):
        task = self._bg_task
        if task is None:
            if self._fatal_error is not None:
                raise self._fatal_error
            if self._has_started:
                return
            raise RuntimeError("WORKER_NOT_STARTED")
        # Waiting on a set does not cancel the Worker when the observer is cancelled.
        await asyncio.wait({task})
        self._observe_bg_task(task)
        if self._fatal_error is not None:
            raise self._fatal_error

    @property
    def is_healthy(self):
        task = self._bg_task
        return (self._fatal_error is None and self.running and
                task is not None and not task.done())

    async def stop(self):
        async with self._lifecycle_lock:
            task = self._bg_task
            if task is not None and task.done():
                self._observe_bg_task(task)
            self.running = False
            if task is not None:
                if not task.done():
                    task.cancel()
                    done, _ = await asyncio.wait({task}, timeout=self.shutdown_timeout)
                    if task not in done:
                        if self._fatal_error is None:
                            self._fatal_error = TimeoutError("WORKER_TASK_STOP_TIMEOUT")
                        raise self._fatal_error
                self._observe_bg_task(task)
            cleanup_error = None
            if self.pool is not None:
                if self._close_task is None:
                    self._close_task = asyncio.create_task(self.pool.close())
                    # Retain ownership even if the shutdown caller is cancelled.
                    self._close_task.add_done_callback(
                        lambda task: None if task.cancelled() else task.exception())
                close_task = self._close_task
                # asyncio.wait does not cancel the child when the caller is cancelled.
                done, _ = await asyncio.wait({close_task}, timeout=self.shutdown_timeout)
                if close_task not in done:
                    close_task.cancel()
                    cleanup_error = TimeoutError("WORKER_POOL_CLOSE_TIMEOUT")
                else:
                    self._close_task = None
                    if close_task.cancelled():
                        cleanup_error = RuntimeError("WORKER_POOL_CLOSE_CANCELLED")
                    else:
                        cleanup_error = close_task.exception()
                        if cleanup_error is None:
                            self.pool = None
            if self._fatal_error is not None:
                if cleanup_error is not None:
                    logger.error("WORKER_POOL_CLEANUP_FAILED_AFTER_FATAL")
                    if hasattr(self._fatal_error, "add_note"):
                        self._fatal_error.add_note("Worker pool cleanup failed; original failure retained.")
                raise self._fatal_error
            if cleanup_error is not None:
                raise cleanup_error
            self._bg_task = None

    async def _process_loop(self):
        while self.running:
            event = None
            try:
                event = await self._acquire_lease()
                if not event:
                    await asyncio.sleep(self.poll_interval)
                    continue

                outcome = await self._dispatch_event(event)
                if outcome.succeeded:
                    # --- E7 FAILPOINT ---
                    failpoint = os.environ.get("E7_FAILPOINT", "")
                    failpoint_event_id = os.environ.get("E7_FAILPOINT_EVENT_ID", "")
                    if failpoint == "after_provider_success_before_finalize" and str(event["event_id"]) == failpoint_event_id:
                        if not (os.environ.get("E7_TEST_MODE") == "1" and os.environ.get("ENVIRONMENT", "").lower() == "test"):
                            raise RuntimeError("E7 failpoint requires strict test environment.")
                        logger.error(f"E7_FAILPOINT_REACHED intent_id={event['event_id']} provider_status=200")
                        await asyncio.Event().wait()
                    # --------------------
                    await self._mark_completed(event["event_id"], event["lease_token"], outcome.provider_reference)
                else:
                    await self._handle_failure(
                        event["event_id"],
                        event["lease_token"],
                        outcome.dispatch_attempt_count,
                        error_msg=outcome.error_code,
                    )
            except asyncio.CancelledError:
                break
            except DispatchAuthorizationError as exc:
                if isinstance(exc, DatabaseIdentityError) or getattr(exc, 'sqlstate', None) == '42501' or ((exc.__cause__ is not None or exc.__context__ is not None) and _dq_has_authority_denial_in_chain(exc)):
                    raise
                if isinstance(exc, DispatchExecutionBarrierError) or _dq_has_execution_barrier_in_chain(exc):
                    raise
                if event is None:
                    logger.error(
                        "[%s] Authorization error occurred without a leased event: %s",
                        self.worker_id,
                        exc.reason_code,
                    )
                    await asyncio.sleep(self.poll_interval)
                    continue

                try:
                    if exc.terminal:
                        finalized = await self._mark_authorization_denied(
                            event,
                            exc.reason_code,
                        )
                        if not finalized:
                            logger.warning(
                                "[%s] Authorization denial was not finalized; "
                                "the lease may have been superseded.",
                                self.worker_id,
                            )
                    else:
                        rescheduled = await self._handle_authorization_failure(
                            event,
                            reason_code=exc.reason_code,
                        )
                        if not rescheduled:
                            logger.warning(
                                "[%s] Authorization retry was not rescheduled; "
                                "the lease may have expired or been superseded.",
                                self.worker_id,
                            )
                except Exception as persist_error:
                    if isinstance(persist_error, DatabaseIdentityError) or getattr(persist_error, 'sqlstate', None) == '42501' or ((persist_error.__cause__ is not None or persist_error.__context__ is not None) and _dq_has_authority_denial_in_chain(persist_error)):
                        raise
                    logger.error(
                        "[%s] Could not persist authorization outcome; "
                        "dispatch remains blocked and the lease will expire: %s",
                        self.worker_id,
                        persist_error,
                    )
                    await asyncio.sleep(self.poll_interval)
            except Exception as e:
                if isinstance(e, DatabaseIdentityError) or getattr(e, 'sqlstate', None) == '42501' or ((e.__cause__ is not None or e.__context__ is not None) and _dq_has_authority_denial_in_chain(e)):
                    raise
                logger.error(f"[{self.worker_id}] Error in outbox loop: {e}")
                await asyncio.sleep(self.poll_interval)


    async def _acquire_lease(self):
        query = "SELECT * FROM public.claim_next_outbox_event($1::text, $2::integer, $3::double precision)"
        async with self.pool.acquire() as conn:
            return await conn.fetchrow(query, self.worker_id, self.max_attempts, self.lease_seconds)

    async def _authorize_before_dispatch(self, event) -> None:
        gate = self.authorization_gate

        if gate is None:
            raise DispatchAuthorizationError("AUTHORIZATION_GATE_NOT_CONFIGURED", terminal=False)

        authorize = getattr(gate, "authorize_before_dispatch", None)
        if not callable(authorize):
            raise DispatchAuthorizationError("INVALID_AUTHORIZATION_GATE", terminal=False)

        try:
            result = authorize(event)

            if not inspect.isawaitable(result):
                raise DispatchAuthorizationError("ASYNC_GATE_REQUIRED", terminal=False)

            allowed = await result

        except DispatchAuthorizationError:
            raise
        except Exception as exc:
            if isinstance(exc, DatabaseIdentityError) or getattr(exc, 'sqlstate', None) == '42501' or ((exc.__cause__ is not None or exc.__context__ is not None) and _dq_has_authority_denial_in_chain(exc)):
                raise
            if _dq_has_execution_barrier_in_chain(exc):
                raise DispatchExecutionBarrierError("STRICT_PROVIDER_EXECUTION_BARRIER", terminal=False) from exc
            raise DispatchAuthorizationError("AUTHORIZATION_CHECK_FAILED", terminal=False) from exc

        if allowed is False:
            raise DispatchAuthorizationError("POLICY_DENIED", terminal=True)

        if allowed is not True:
            raise DispatchAuthorizationError("INVALID_AUTHORIZATION_RESULT", terminal=False)

    async def _dispatch_event(self, event) -> DispatchOutcome:
        # Authorization must finish before payload processing or network access.
        await self._authorize_before_dispatch(event)

        # Persist a lease-fenced provider-attempt marker before any HTTP request.
        dispatch_attempt_count = await self._mark_dispatch_started(event)
        if type(dispatch_attempt_count) is not int or dispatch_attempt_count < 1:
            raise RuntimeError(
                "Provider dispatch was suppressed because its start marker "
                "could not be committed."
            )

        raw_payload = event["payload"]
        if isinstance(raw_payload, str):
            try:
                payload = json.loads(raw_payload)
            except Exception:
                payload = raw_payload
        else:
            payload = raw_payload

        event_id_str = str(event["event_id"])
        headers = {
            "Content-Type": "application/json",
            "Idempotency-Key": event_id_str,
            "X-Event-ID": event_id_str,
        }

        urls = [self.provider_url]
        if "localhost" in self.provider_url:
            urls.append(self.provider_url.replace("localhost", "127.0.0.1"))
        elif "127.0.0.1" in self.provider_url:
            urls.append(self.provider_url.replace("127.0.0.1", "localhost"))

        last_err = None
        for base_url in urls:
            try:
                async with httpx.AsyncClient(timeout=self.request_timeout) as client:
                    response = await client.post(
                        f"{base_url}/v1/events",
                        json={"event_type": event["event_type"], "data": payload},
                        headers=headers,
                    )
                    if response.status_code in (200, 201, 202):
                        try:
                            body = response.json()
                        except Exception:
                            body = None
                        if not isinstance(body, dict):
                            last_err = "Provider returned a non-object or malformed JSON success response"
                        elif not isinstance(body.get("status"), str) or body["status"].lower() not in {"success", "succeeded"}:
                            last_err = "Provider success response did not contain an explicit success status"
                        else:
                            provider_reference = body.get("provider_id") or body.get("provider_reference")
                            if not isinstance(provider_reference, str) or not provider_reference.strip():
                                last_err = "Provider success response did not contain a stable provider reference"
                            else:
                                return DispatchOutcome(
                                    succeeded=True,
                                    provider_reference=provider_reference.strip(),
                                    dispatch_attempt_count=dispatch_attempt_count,
                                )
                    else:
                        last_err = f"HTTP {response.status_code}: {response.text[:200]}"
            except Exception as e:
                last_err = f"Transport error to {base_url}: {e}"
                logger.warning(f"[{self.worker_id}] Error dispatching event {event_id_str} to {base_url}: {e}")

        return DispatchOutcome(
            succeeded=False,
            error_code=last_err or "Unknown dispatch failure",
            dispatch_attempt_count=dispatch_attempt_count,
        )


    async def _mark_dispatch_started(self, event) -> int | None:
        """Commit a provider-attempt marker under the current lease fence."""
        event_id = UUID(str(event["event_id"]))
        lease_token = UUID(str(event["lease_token"]))

        if self.pool is None:
            raise RuntimeError("Cannot mark dispatch without a database pool.")

        query = (
            "SELECT public.begin_outbox_dispatch_attempt_v1("
            "$1::uuid, $2::uuid, $3::integer)"
        )

        async with self.pool.acquire() as conn:
            result = await conn.fetchval(
                query,
                event_id,
                lease_token,
                self.max_attempts,
            )

        if result is None:
            return None
        if type(result) is not int or result < 1:
            raise RuntimeError("Database returned an invalid dispatch-attempt count.")
        return result

    async def _handle_authorization_failure(
        self,
        event,
        reason_code: str,
    ) -> bool:
        """Retry an unavailable authorization check without consuming provider attempts."""
        if self.pool is None:
            raise RuntimeError(
                "Cannot persist authorization retry without a database pool."
            )

        if not isinstance(reason_code, str) or not reason_code:
            reason_code = "AUTHORIZATION_CHECK_FAILED"

        lease_count = max(1, int(event.get("attempt_count", 1) or 1))
        delay_seconds = self._calculate_backoff(lease_count)

        query = (
            "SELECT public.reschedule_outbox_authorization_check_v1("
            "$1::uuid, $2::uuid, $3::double precision, $4::text)"
        )

        async with self.pool.acquire() as conn:
            result = await conn.fetchval(
                query,
                UUID(str(event["event_id"])),
                UUID(str(event["lease_token"])),
                delay_seconds,
                f"Authorization unavailable: {reason_code}"[:500],
            )
            return bool(result)

    async def _mark_authorization_denied(self, event, reason_code: str) -> bool:
        """Persist a terminal denial through a lease-fenced database function."""
        allowed_reason_codes = {"POLICY_DENIED"}

        if not isinstance(reason_code, str) or reason_code not in allowed_reason_codes:
            raise ValueError("Unsupported authorization denial reason code.")

        event_id = UUID(str(event["event_id"]))
        lease_token = UUID(str(event["lease_token"]))

        if self.pool is None:
            raise RuntimeError("Cannot persist authorization denial without a database pool.")

        query = (
            "SELECT public.deny_outbox_event_v1("
            "$1::uuid, $2::uuid, $3::text)"
        )

        async with self.pool.acquire() as conn:
            result = await conn.fetchval(
                query,
                event_id,
                lease_token,
                reason_code,
            )
            return bool(result)

    async def _mark_completed(self, event_id, lease_token, provider_reference: str | None = None) -> bool:
        query = "SELECT public.finalize_outbox_event_v2($1::uuid, $2::uuid, 'SUCCEEDED', $3::text, NULL::text)"
        async with self.pool.acquire() as conn:
            result = await conn.fetchval(query, event_id, lease_token, provider_reference)
            return bool(result)

    def _calculate_backoff(self, attempt_count: int) -> float:
        # Authorization checks can retry independently of provider attempts.
        # Saturate iteratively to avoid constructing enormous integers.
        exponent = max(0, int(attempt_count) - 1)
        cap = max(0.0, float(self.max_backoff_seconds))
        backoff = min(max(0.0, float(self.base_backoff_seconds)), cap)

        for _ in range(min(exponent, 64)):
            if backoff >= cap:
                break
            backoff = min(cap, backoff * 2.0)

        return random.uniform(0.5, 1.0) * backoff


    async def _handle_failure(
        self,
        event_id,
        lease_token,
        dispatch_attempt_count,
        error_msg: str = None,
    ) -> bool:
        if dispatch_attempt_count < 1:
            raise ValueError(
                "Provider failure handling requires a persisted dispatch attempt."
            )

        if dispatch_attempt_count >= self.max_attempts:
            query = (
                "SELECT public.finalize_outbox_event_v2("
                "$1::uuid, $2::uuid, 'RECONCILIATION_REQUIRED', NULL::text, $3::text)"
            )
            async with self.pool.acquire() as conn:
                result = await conn.fetchval(
                    query,
                    event_id,
                    lease_token,
                    (error_msg or "Provider outcome ambiguous")[:500],
                )
                return bool(result)

        delay_seconds = self._calculate_backoff(dispatch_attempt_count)
        query = (
            "SELECT public.reschedule_outbox_event("
            "$1::uuid, $2::uuid, $3::double precision, $4::text, $5::integer)"
        )
        async with self.pool.acquire() as conn:
            result = await conn.fetchval(
                query,
                event_id,
                lease_token,
                delay_seconds,
                (error_msg or "Dispatch failed")[:500],
                self.max_attempts,
            )
            return bool(result)
