"""Serialization helpers.

Double-ratchet state contains private key material. Any persisted form must be
protected at rest (e.g. encrypted and integrity-protected) by the caller.
"""

from __future__ import annotations

import base64
from typing import Any, Mapping

from .ratchet import RatchetState
from .x25519 import X25519KeyPair, x25519_private_from_bytes, x25519_public_from_bytes


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def serialize_ratchet_state(state: RatchetState) -> dict[str, Any]:
    """Serialize a :class:`~darkhole.crypto.ratchet.RatchetState` to a JSON-safe dict."""

    return {
        "root_key": _b64e(state.root_key),
        "dh_self_private": _b64e(state.dh_self.private_bytes()),
        "dh_self_public": _b64e(state.dh_self.public_bytes()),
        "dh_remote_public": _b64e(state.dh_remote_public_bytes()),
        "ck_s": None if state.ck_s is None else _b64e(state.ck_s),
        "ck_r": None if state.ck_r is None else _b64e(state.ck_r),
        "ns": state.ns,
        "nr": state.nr,
        "pn": state.pn,
        "max_skip": state.max_skip,
        "mk_skipped": [
            {"dh": _b64e(dh), "n": n, "mk": _b64e(mk)} for (dh, n), mk in state.mk_skipped.items()
        ],
    }


def deserialize_ratchet_state(blob: Mapping[str, Any]) -> RatchetState:
    """Deserialize a state produced by :func:`serialize_ratchet_state`."""

    root_key = _b64d(str(blob["root_key"]))
    dh_self_private = x25519_private_from_bytes(_b64d(str(blob["dh_self_private"])))
    dh_self_public = x25519_public_from_bytes(_b64d(str(blob["dh_self_public"])))

    dh_remote_public = x25519_public_from_bytes(_b64d(str(blob["dh_remote_public"])))

    ck_s_v = blob.get("ck_s")
    ck_r_v = blob.get("ck_r")

    ck_s = None if ck_s_v in (None, "") else _b64d(str(ck_s_v))
    ck_r = None if ck_r_v in (None, "") else _b64d(str(ck_r_v))

    keypair = X25519KeyPair(private=dh_self_private, public=dh_self_public)

    mk_skipped_list = blob.get("mk_skipped", [])
    mk_skipped: dict[tuple[bytes, int], bytes] = {}
    for item in mk_skipped_list:
        dh = _b64d(str(item["dh"]))
        n = int(item["n"])
        mk = _b64d(str(item["mk"]))
        mk_skipped[(dh, n)] = mk

    return RatchetState(
        root_key=root_key,
        dh_self=keypair,
        dh_remote_public=dh_remote_public,
        ck_s=ck_s,
        ck_r=ck_r,
        ns=int(blob.get("ns", 0)),
        nr=int(blob.get("nr", 0)),
        pn=int(blob.get("pn", 0)),
        mk_skipped=mk_skipped,
        max_skip=int(blob.get("max_skip", 1000)),
    )
