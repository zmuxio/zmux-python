"""Fixtures shared by the transport tests."""

import pytest

import zmux
from support import Tls


@pytest.fixture(scope="module")
def tls() -> Tls:
    pytest.importorskip("cryptography")  # no 32-bit Windows wheels
    from certs import self_signed

    cert_pem, key_pem = self_signed()
    return zmux.TlsConfig(cert=cert_pem, key=key_pem), zmux.TlsConfig(ca=cert_pem)
