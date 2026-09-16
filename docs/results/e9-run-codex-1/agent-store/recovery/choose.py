from __future__ import annotations

from ..codec import decode_super
from ..format import NO_PAGE, TYPE_SUPER, header_ok, unpack_header
from .walk import collect_snapshot


def _candidate(pages: list[bytes], slot: int) -> dict | None:
    if slot >= len(pages):
        return None
    page = pages[slot]
    if not header_ok(page) or page[28:32] != b"\x00" * 4:
        return None
    hdr = unpack_header(page)
    if (
        hdr["type"] != TYPE_SUPER
        or hdr["flags"] != 0
        or hdr["nkeys"] != 0
        or hdr["right_sibling"] != NO_PAGE
        or hdr["child0"] != NO_PAGE
        or hdr["lsn"] <= 0
    ):
        return None
    try:
        sb = decode_super(page)
    except Exception:
        return None
    if sb["slot"] != slot or sb["root_lsn"] != sb["lsn"]:
        return None
    if sb["free_head"] != NO_PAGE and not (2 <= sb["free_head"] < sb["page_count"]):
        return None
    if sb["wal_head"] == NO_PAGE or not (2 <= sb["wal_head"] < sb["page_count"]):
        return None
    if collect_snapshot(pages, sb) is None:
        return None
    return sb


def choose_super(pages: list[bytes]) -> dict | None:
    candidates = [sb for slot in (0, [REDACTED]) if (sb := _candidate(pages, slot)) is not None]
    if not candidates:
        return None
    return max(candidates, key=lambda sb: (sb["lsn"], sb["slot"]))
