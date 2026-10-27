#!/usr/bin/env python3
"""
Simulates the failure pattern in Cloudflare's 2026-10-26 postmortem,
"Cross-request KV cache exposure in the GLM-5.3 Workers AI model, and our
remediation with SGLang" (blog.cloudflare.com/kv-cache-exposure-remediation),
and SGLang's own security update (lmsys.org/blog/2026-10-26-cf-security).

This is a from-scratch, in-memory model of the failure mode, sized to run in
a terminal in a few seconds. It is NOT the real SGLang or Cloudflare code,
uses no proprietary source, and needs no GPU, no SGLang install, and no
network access. It reproduces the SHAPE of the bug two public postmortems
described, with page counts and tenant labels standing in for real KV
tensors, so the mechanism is visible without 681,280 real tokens of state.

Root cause, per the two postmortems:
  1. Cloudflare deployed GLM-5.3 with a context window (1,048,576 tokens)
     larger than its prefill GPUs' KV cache pool (681,280 tokens) -- a
     mismatch Cloudflare says it knew about before launch.
  2. SGLang's disaggregated prefill/decode admission queue checked whether a
     request was FINISHED, not whether it had been REJECTED. An over-length
     request got marked rejected but kept moving through the pipeline with
     its prompt swapped for a one-token placeholder.
  3. Prefill transferred the one placeholder token into the request's first
     reserved KV page. Decode then attended over ALL of the request's
     reserved pages (the postmortems describe 8 reserved pages per slot) --
     including pages the allocator had already reused from an earlier,
     unrelated request, because pages are not zeroed on free (that would
     cost a write on every request, for a bug nobody had hit yet).
  4. The response blended the placeholder with whatever tenant's data was
     still sitting in those stale pages. The client received HTTP 200.

This script models exactly that: a fixed-size page pool, pages that are
freed-but-not-cleared, and two admission policies -- "vulnerable" (checks
.finished, the real bug) and "fixed" (checks .rejected and retires the
request before any page touches the pool, the real patch, upstreamed as
SGLang #38704).
"""
from __future__ import annotations

import argparse
import textwrap
from dataclasses import dataclass, field

PAGES_PER_SLOT = 8        # reserved KV pages per request slot (illustrative)
POOL_CAPACITY_PAGES = 1    # pages a request may actually fill before it is over budget


@dataclass
class Page:
    owner: str | None = None
    content: str | None = None


@dataclass
class Request:
    tenant: str
    tokens_needed_pages: int
    secret: str
    rejected: bool = False
    finished: bool = False


class PagePool:
    """A fixed-size pool of KV pages. Freed pages are NOT zeroed -- matching
    the real allocators this bug lives in, where clearing on free costs a
    write on every single request to guard against a bug nobody has hit."""

    def __init__(self, num_pages: int):
        self.pages = [Page() for _ in range(num_pages)]

    def write(self, slot_start: int, count: int, owner: str, content: str) -> None:
        for i in range(slot_start, slot_start + count):
            self.pages[i] = Page(owner=owner, content=content)

    def free(self, slot_start: int, count: int) -> None:
        # Real bug, modeled faithfully: free does NOT clear page contents.
        pass

    def read_slot(self, slot_start: int, count: int) -> list[Page]:
        return self.pages[slot_start : slot_start + count]


def admit_vulnerable(req: Request, pool_capacity: int) -> None:
    """The real bug: over-length requests are marked rejected, but the
    admission queue only checks `finished`, so the rejected request is NOT
    retired -- it keeps moving through prefill and decode."""
    if req.tokens_needed_pages > pool_capacity:
        req.rejected = True
        # BUG: no `return` / no retirement here. Falls through to prefill.


def admit_fixed(req: Request, pool_capacity: int) -> bool:
    """The patch (upstreamed as SGLang #38704): a pending rejection is
    retired at the admission queue, before any page allocation or transfer.
    Returns False if the request was rejected and must not proceed."""
    if req.tokens_needed_pages > pool_capacity:
        req.rejected = True
        return False
    return True


def run_vulnerable(pool: PagePool, slot_start: int, tenant_a: Request, tenant_b: Request) -> str:
    # Tenant A's request fits, fills its full slot with real content, then
    # the slot is freed for reuse -- pages still hold A's bytes.
    pool.write(slot_start, PAGES_PER_SLOT, tenant_a.tenant, tenant_a.secret)
    pool.free(slot_start, PAGES_PER_SLOT)

    # Tenant B's over-length request reuses the same slot.
    admit_vulnerable(tenant_b, POOL_CAPACITY_PAGES)
    # Prefill only ever transfers the one-token placeholder (POOL_CAPACITY_PAGES
    # worth) -- it never finishes writing the rest of the reserved slot.
    pool.write(slot_start, POOL_CAPACITY_PAGES, tenant_b.tenant, "<placeholder-token>")

    # Decode attends over the FULL reserved slot regardless -- that's the bug.
    slot = pool.read_slot(slot_start, PAGES_PER_SLOT)
    response = " | ".join(f"{p.owner}:{p.content}" for p in slot)
    tenant_b.finished = True
    return response


def run_fixed(pool: PagePool, slot_start: int, tenant_a: Request, tenant_b: Request) -> str:
    pool.write(slot_start, PAGES_PER_SLOT, tenant_a.tenant, tenant_a.secret)
    pool.free(slot_start, PAGES_PER_SLOT)

    ok = admit_fixed(tenant_b, POOL_CAPACITY_PAGES)
    if not ok:
        # Retired before touching the pool. No prefill, no transfer, no decode.
        return "HTTP 400: request rejected (context length exceeds KV pool capacity)"

    pool.write(slot_start, PAGES_PER_SLOT, tenant_b.tenant, tenant_b.secret)
    slot = pool.read_slot(slot_start, PAGES_PER_SLOT)
    return " | ".join(f"{p.owner}:{p.content}" for p in slot)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--engine", choices=["vulnerable", "fixed", "both"], default="both")
    args = parser.parse_args()

    tenant_a = Request(tenant="tenant-A", tokens_needed_pages=PAGES_PER_SLOT, secret="PROJECT_ZEPHYR_Q4_FORECAST")
    tenant_b_template = dict(tenant="tenant-B", tokens_needed_pages=PAGES_PER_SLOT + 4, secret="tenant-B's own long prompt")

    pool_size = PAGES_PER_SLOT  # one slot, reused between tenants, like the real failure
    print(f"Pool: {pool_size} pages/slot, {POOL_CAPACITY_PAGES} page(s) of real prefill capacity per request\n")

    if args.engine in ("vulnerable", "both"):
        pool = PagePool(pool_size)
        tenant_b = Request(**tenant_b_template)
        result = run_vulnerable(pool, 0, tenant_a, tenant_b)
        print("=== vulnerable engine (admission checks `.finished`, matches the pre-patch SGLang) ===")
        print(f"tenant-B sends a request longer than the KV pool can hold.")
        print(f"tenant-B's response : {result}")
        leaked = tenant_a.tenant in result and tenant_b.tenant != tenant_a.tenant
        print(f"HTTP status reported to tenant-B: 200 OK")
        print(f"LEAK: tenant-B's response contains tenant-A's data -> {leaked}\n")

    if args.engine in ("fixed", "both"):
        pool = PagePool(pool_size)
        tenant_b = Request(**tenant_b_template)
        result = run_fixed(pool, 0, tenant_a, tenant_b)
        print("=== fixed engine (admission checks `.rejected`, matches SGLang #38704 / v0.5.21+) ===")
        print(f"tenant-B sends the same over-length request.")
        print(f"tenant-B's response : {result}\n")

    print(textwrap.dedent("""\
        This is a simulation of the bug's SHAPE, not the real SGLang engine.
        Real numbers from Cloudflare's postmortem: 1,048,576-token configured
        context window vs. 681,280-token prefill KV pool, 155 affected
        responses between 2026-08-27 and 2026-09-09, fixed by raising the pool
        to ~2.04M tokens and retiring rejected requests at admission (SGLang
        #38704, upstreamed in v0.5.21/v0.5.22)."""))


if __name__ == "__main__":
    main()
