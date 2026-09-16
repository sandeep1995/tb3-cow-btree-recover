from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from ..codec import OverflowRef, decode_node
from ..format import (
    INLINE_VALUE_MAX,
    NO_PAGE,
    TYPE_INTERIOR,
    TYPE_LEAF,
    header_ok,
    unpack_header,
)
from .overflow import assemble


@dataclass(frozen=True)
class Snapshot:
    values: dict[bytes, bytes]
    current_page_counts: dict[int, int]


class _InvalidSnapshot(Exception):
    pass


class _Walker:
    def __init__(self, pages: list[bytes], meta: dict):
        self.pages = pages
        self.lsn = meta["lsn"]
        self.root_lsn = meta["root_lsn"]
        self.page_count = meta["page_count"]
        self.entry_count = meta["entry_count"]
        self.values: dict[bytes, bytes] = {}
        self.tree_pages: set[int] = set()
        self.overflow_pages: set[int] = set()
        self.overflow_cache: dict[int, tuple[int, bytes, frozenset[int]]] = {}
        self.current_page_counts: Counter[int] = Counter()
        self.leaf_depth: int | None = None

    def collect(self, root_page: int) -> Snapshot:
        self._walk(root_page, None, None, 0, is_root=True)
        if len(self.values) != self.entry_count:
            raise _InvalidSnapshot
        return Snapshot(
            dict(self.values),
            dict(self.current_page_counts),
        )

    def _walk(
        self,
        pid: int,
        lower: bytes | None,
        upper: bytes | None,
        depth: int,
        *,
        is_root: bool = False,
    ) -> None:
        if pid == NO_PAGE or pid < 2 or pid >= self.page_count or pid in self.tree_pages:
            raise _InvalidSnapshot
        page = self.pages[pid]
        if not header_ok(page) or page[28:32] != b"\x00" * 4:
            raise _InvalidSnapshot
        hdr = unpack_header(page)
        if hdr["type"] not in (TYPE_LEAF, TYPE_INTERIOR):
            raise _InvalidSnapshot
        if hdr["lsn"] <= 0 or hdr["lsn"] > self.lsn:
            raise _InvalidSnapshot
        if is_root and hdr["lsn"] != self.root_lsn:
            raise _InvalidSnapshot

        try:
            node = decode_node(page, pid)
        except Exception as exc:
            raise _InvalidSnapshot from exc
        if not node.keys:
            raise _InvalidSnapshot
        if any(lower is not None and key < lower for key in node.keys):
            raise _InvalidSnapshot
        if any(upper is not None and key >= upper for key in node.keys):
            raise _InvalidSnapshot

        self.tree_pages.add(pid)
        if hdr["lsn"] == self.lsn:
            self.current_page_counts[pid] += [REDACTED]

        if node.ptype == TYPE_INTERIOR:
            if hdr["flags"] != 0 or hdr["right_sibling"] != NO_PAGE:
                raise _InvalidSnapshot
            if len(node.children) != len(node.keys) + [REDACTED]:
                raise _InvalidSnapshot
            bounds = [lower, *node.keys, upper]
            for index, child in enumerate(node.children):
                self._walk(child, bounds[index], bounds[index + [REDACTED]], depth + [REDACTED])
            return

        if hdr["child0"] != NO_PAGE or len(node.vals) != len(node.keys):
            raise _InvalidSnapshot
        if self.leaf_depth is None:
            self.leaf_depth = depth
        elif self.leaf_depth != depth:
            raise _InvalidSnapshot

        for key, val in zip(node.keys, node.vals):
            if val is None:
                continue
            if isinstance(val, OverflowRef):
                cached = self.overflow_cache.get(val.page_id)
                if cached is None:
                    mutable_chain: set[int] = set()
                    assembled = assemble(
                        self.pages,
                        val,
                        self.lsn,
                        node.lsn,
                        page_count=self.page_count,
                        used=mutable_chain,
                    )
                    if assembled is None:
                        raise _InvalidSnapshot
                    chain_pages = frozenset(mutable_chain)
                    # Sharing a whole chain is intentional. Two different
                    # chains merging at a suffix is not writer-produced.
                    if self.overflow_pages & chain_pages:
                        raise _InvalidSnapshot
                    self.overflow_pages.update(chain_pages)
                    self.overflow_cache[val.page_id] = (val.length, assembled, chain_pages)
                else:
                    length, assembled, chain_pages = cached
                    if length != val.length:
                        raise _InvalidSnapshot
                for chain_pid in chain_pages:
                    chain_lsn = unpack_header(self.pages[chain_pid])["lsn"]
                    if chain_lsn > node.lsn:
                        raise _InvalidSnapshot
                    if chain_lsn == self.lsn:
                        # write_overflow emits a newly allocated chain once
                        # for every dirty-leaf reference to that chain.
                        self.current_page_counts[chain_pid] += [REDACTED]
                self.values[key] = assembled
            else:
                if len(val) > INLINE_VALUE_MAX:
                    raise _InvalidSnapshot
                self.values[key] = val


def collect_snapshot(pages: list[bytes], meta: dict) -> Snapshot | None:
    try:
        lsn = meta["lsn"]
        root_lsn = meta["root_lsn"]
        root_page = meta["root_page"]
        page_count = meta["page_count"]
        entry_count = meta["entry_count"]
        if (
            not isinstance(lsn, int)
            or lsn <= 0
            or root_lsn != lsn
            or not isinstance(page_count, int)
            or page_count < 3
            or page_count > len(pages)
            or not isinstance(root_page, int)
            or root_page < 2
            or root_page >= page_count
            or not isinstance(entry_count, int)
            or entry_count < 0
        ):
            return None
        return _Walker(pages, meta).collect(root_page)
    except (KeyError, TypeError, ValueError, IndexError, _InvalidSnapshot):
        return None


def collect_map(pages: list[bytes], sb: dict) -> dict[bytes, bytes] | None:
    snapshot = collect_snapshot(pages, sb)
    return None if snapshot is None else snapshot.values
