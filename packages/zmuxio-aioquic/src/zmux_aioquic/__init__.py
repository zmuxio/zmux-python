"""Optional aioquic stream adapter for the stable zmux async API."""

from __future__ import annotations

from ._constants import (
    ACCEPTED_PRELUDE_RESULT_QUEUE_CAP,
    DEFAULT_ACCEPTED_PRELUDE_MAX_CONCURRENT,
    DEFAULT_ACCEPTED_PRELUDE_READ_TIMEOUT,
    MAX_ACCEPTED_PRELUDE_MAX_CONCURRENT,
    OPEN_METADATA_CAPABILITIES,
    STREAM_PRELUDE_MAX_PAYLOAD,
    WRITEV_COALESCE_MAX_BYTES,
)
from ._errors import (
    translate_error,
    translate_open_error,
    translate_read_error,
    translate_write_error,
)
from ._options import (
    SessionOptions,
    default_accepted_prelude_max_concurrent,
    normalize_accepted_prelude_max_concurrent,
    normalize_accepted_prelude_read_timeout,
    set_default_accepted_prelude_max_concurrent,
)
from ._prelude import AcceptedStreamMetadata, build_stream_prelude, read_stream_prelude
from ._session import (
    AioquicSession,
    target_claims,
    target_implementation_profiles,
    target_suites,
    wrap_session,
)
from ._stream import AioquicRecvStream, AioquicSendStream, AioquicStream

__all__ = (
    "ACCEPTED_PRELUDE_RESULT_QUEUE_CAP",
    "AioquicRecvStream",
    "AioquicSendStream",
    "AioquicSession",
    "AioquicStream",
    "AcceptedStreamMetadata",
    "DEFAULT_ACCEPTED_PRELUDE_MAX_CONCURRENT",
    "DEFAULT_ACCEPTED_PRELUDE_READ_TIMEOUT",
    "MAX_ACCEPTED_PRELUDE_MAX_CONCURRENT",
    "OPEN_METADATA_CAPABILITIES",
    "STREAM_PRELUDE_MAX_PAYLOAD",
    "SessionOptions",
    "WRITEV_COALESCE_MAX_BYTES",
    "build_stream_prelude",
    "default_accepted_prelude_max_concurrent",
    "normalize_accepted_prelude_max_concurrent",
    "normalize_accepted_prelude_read_timeout",
    "read_stream_prelude",
    "set_default_accepted_prelude_max_concurrent",
    "target_claims",
    "target_implementation_profiles",
    "target_suites",
    "translate_error",
    "translate_open_error",
    "translate_read_error",
    "translate_write_error",
    "wrap_session",
)
