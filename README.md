# Cloudflare GLM-5.3 KV cache leak (sim)

> 📖 **Read the write-up:** coming soon on [webofmike.com](https://webofmike.com)

A from-scratch, in-memory simulation of the bug pattern Cloudflare and the
SGLang project described in two public postmortems published 2026-10-26:

- Cloudflare: ["Cross-request KV cache exposure in the GLM-5.3 Workers AI model, and our remediation with SGLang"](https://blog.cloudflare.com/kv-cache-exposure-remediation)
- SGLang / LMSYS: ["SGLang security update: improving request isolation"](https://www.lmsys.org/blog/2026-10-26-cf-security)

Between 2026-08-27 and 2026-09-09, 155 responses from the `@cf/zai-org/glm-5.3`
model on Cloudflare Workers AI contained fragments of other tenants' KV cache
state. Two things had to go wrong together:

1. **A sizing mismatch Cloudflare says it knew about before launch.**
   GLM-5.3 was deployed with a 1,048,576-token context window, but the
   prefill GPUs' KV cache pool only had room for 681,280 tokens.
2. **An SGLang bug in disaggregated prefill/decode mode.** The admission
   queue checked whether a request was *finished*, not whether it had been
   *rejected*. An over-length request got marked rejected but kept moving:
   its prompt was swapped for a one-token placeholder, prefill transferred
   that one token, and decode attended over all of the request's reserved
   KV pages anyway -- including pages the allocator had already reused from
   an earlier, unrelated request, because freed pages are not zeroed.

The client got HTTP 200. The response was spliced from two tenants.

## The value proposition this maps to

If you run, or route traffic to, a disaggregated LLM-serving backend
(SGLang, vLLM's PD split, or anything with the same prefill/decode handoff
shape), this is the failure mode to check for before it checks you:
**rejected requests must be retired before they touch shared memory, not
after.** An admission check that only asks "is this done?" instead of "was
this allowed?" will eventually let a request with no real content walk
through a code path built for requests with content -- and inherit whatever
was already sitting in the buffer it was handed. An AI gateway or router
sitting in front of a shared inference backend is exactly the layer that
should be enforcing (or at least monitoring for) that invariant, since it's
often the only component that sees every tenant's traffic in one place.

## Quickstart

```bash
git clone https://github.com/themsquared/cloudflare-glm-kv-cache-leak.git
cd cloudflare-glm-kv-cache-leak
python3 scripts/demo.py
```

No dependencies beyond Python 3.10+ (stdlib only), no GPU, no SGLang
install, no network calls. Runs in under a second.

```bash
python3 scripts/demo.py --engine vulnerable   # just the leak
python3 scripts/demo.py --engine fixed        # just the patched behavior
python3 scripts/demo.py --engine both         # default: side by side
```

## What it shows

A single fixed-size KV page pool (8 pages per request slot, matching the
reserved-page count the postmortems describe) is reused between two
simulated tenants:

```
=== vulnerable engine (admission checks `.finished`, matches the pre-patch SGLang) ===
tenant-B sends a request longer than the KV pool can hold.
tenant-B's response : tenant-B:<placeholder-token> | tenant-A:PROJECT_ZEPHYR_Q4_FORECAST | tenant-A:PROJECT_ZEPHYR_Q4_FORECAST | ...
HTTP status reported to tenant-B: 200 OK
LEAK: tenant-B's response contains tenant-A's data -> True

=== fixed engine (admission checks `.rejected`, matches SGLang #38704 / v0.5.21+) ===
tenant-B sends the same over-length request.
tenant-B's response : HTTP 400: request rejected (context length exceeds KV pool capacity)
```

`tenant-A` writes its real content into the slot, the slot is "freed" (the
simulator deliberately does **not** clear page contents on free -- matching
the real allocators this bug lives in, where zeroing on every free costs a
write on every single request to guard against a bug nobody has hit yet).
`tenant-B` then sends a request too long for the pool. Under the vulnerable
admission policy, `tenant-B`'s request is marked rejected but is never
retired, so it proceeds through prefill (which only ever writes the one
placeholder page it actually has capacity for) and decode (which reads the
*entire* reserved slot regardless) -- splicing `tenant-A`'s stale bytes into
`tenant-B`'s response while reporting success. Under the fixed policy,
the rejection is checked and the request is retired before it ever touches
the pool.

## What this is not

This is **not** the real SGLang or Cloudflare code, and it does not use any
proprietary source from either. It is a from-scratch model sized to make
the failure's *shape* visible -- fixed-size pages, a reuse-without-clearing
pool, and the two admission policies -- without 681,280 real tokens of GPU
state behind it. Real version numbers, timestamps, and remediation details
are Cloudflare's and SGLang's own public disclosures, linked above; verify
anything load-bearing against those primary sources.

## Further reading

- [SGLang disaggregated serving docs](https://docs.sglang.ai/) for how the
  real prefill/decode split and RDMA transfer work.
- SGLang's own guidance for disaggregated-serving operators: upgrade past
  v0.5.21/v0.5.22, run a router that cancels both halves of a PD pair on
  abort, verify KV pool capacity against configured context length, and
  monitor `sglang:decode_deferred_kv_release_total{outcome}`.

## License

Apache-2.0. See [LICENSE](LICENSE).
