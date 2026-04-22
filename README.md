# pq-dpf-core

Portable DPF core extracted and adapted for PrivateQuery.

This repository provides:

- A standard C++20 implementation of the minimal 2-party DPF CPU path
- A C ABI for backend integration through `cgo`
- Native tests for key generation, point evaluation, full-domain evaluation, and payload aggregation

The implementation is adapted from [myl7/fss](https://github.com/myl7/fss) and keeps the original Apache-2.0 attribution in the source headers and repository metadata.

## Layout

- `include/pq_dpf_core/core.hpp`: portable DPF core
- `include/pq_dpf_core/c_api.h`: C ABI for Go integration
- `src/c_api.cpp`: C ABI implementation
- `tests/core_test.cpp`: native verification entry

## Build Native Test

```bash
./scripts/test_native.sh
```

## Notes

- This v1 core intentionally avoids CUDA, OpenMP, OpenSSL, and AES-NI.
- The output group is fixed to `uint64_t` arithmetic modulo `2^64`.
- The backend uses the C ABI directly.
