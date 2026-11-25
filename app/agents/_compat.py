"""Compatibility shim for optional compiled LangGraph dependencies.

Some managed/enterprise Windows environments block unsigned native extensions
such as ``ormsgpack``. LangGraph imports it unconditionally in its serializer,
so we provide a minimal pure-Python substitute when the extension is missing.
The investigation state is plain JSON, so the JSON-based implementation is
sufficient and keeps the application fully functional.
"""

from __future__ import annotations

import json
import sys
import types
from typing import Any


def install() -> None:
    try:
        import ormsgpack  # noqa: F401
        return
    except (ImportError, OSError):
        pass

    module = types.ModuleType("ormsgpack")

    for option in (
        "OPT_NON_STR_KEYS",
        "OPT_SERIALIZE_PYDANTIC",
        "OPT_PASSTHROUGH_DATACLASS",
        "OPT_PASSTHROUGH_DATETIME",
        "OPT_PASSTHROUGH_ENUM",
        "OPT_PASSTHROUGH_UUID",
        "OPT_UTC_Z",
    ):
        setattr(module, option, 0)

    class Ext:  # pragma: no cover - only used for exotic objects
        def __init__(self, code: int, data: bytes):
            self.code = code
            self.data = data

    class MsgpackEncodeError(ValueError):
        pass

    def packb(obj: Any, **kwargs: Any) -> bytes:
        default = kwargs.get("default")
        return json.dumps(obj, default=default, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def unpackb(data: bytes, **kwargs: Any) -> Any:
        return json.loads(data)

    module.Ext = Ext
    module.MsgpackEncodeError = MsgpackEncodeError
    module.packb = packb
    module.unpackb = unpackb
    module.pack = packb
    module.unpack = unpackb
    sys.modules["ormsgpack"] = module
