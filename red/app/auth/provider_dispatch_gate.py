"""Compose independent authorization with deny-only provider admission.

Research-stage integration. This gate cannot authorize provider dispatch
until a separately verified acceptance-time contract is implemented.
"""

import inspect

from app.auth.provider_admission import (
    ProviderAdmissionRequest,
    StrictProviderAdmission,
)


class StrictProviderBarrierError(RuntimeError):
    """Strict admission succeeded, but provider execution is not enabled."""


class StrictProviderDispatchGate:
    def __init__(self, delegate, request_factory):
        if not callable(getattr(delegate, "authorize_before_dispatch", None)):
            raise TypeError("AUTHORIZATION_DELEGATE_REQUIRED")
        if not callable(request_factory):
            raise TypeError("ADMISSION_REQUEST_FACTORY_REQUIRED")

        self._delegate = delegate
        self._request_factory = request_factory
        self._admission = StrictProviderAdmission()

    async def authorize_before_dispatch(self, event):
        result = self._delegate.authorize_before_dispatch(event)

        if not inspect.isawaitable(result):
            raise RuntimeError("INVALID_AUTHORIZATION_RESULT")

        allowed = await result

        # Preserve the original Worker's fail-closed handling.
        if allowed is not True:
            return allowed

        request = self._request_factory(event)
        if not isinstance(request, ProviderAdmissionRequest):
            raise RuntimeError("INVALID_ADMISSION_REQUEST_FACTORY_RESULT")

        # The current contract always denies unverified providers.
        self._admission.require(request)

        # Deliberately unreachable with the current deny-only contract.
        raise StrictProviderBarrierError("UNEXPECTED_PROVIDER_ADMISSION_RETURN")
