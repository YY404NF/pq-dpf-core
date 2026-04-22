# Attribution

`pq-dpf-core` adapts ideas and implementation structure from:

- [myl7/fss](https://github.com/myl7/fss)
- Relevant upstream files:
  - `include/fss/dpf.cuh`
  - `include/fss/util.cuh`
  - `include/fss/group.cuh`
  - `include/fss/group/uint.cuh`
  - `include/fss/prg/aes128_mmo_soft.cuh`

## Key adaptations

- Replaced CUDA `int4` with project-local `Block128`
- Replaced `cuda::std::*` and device annotations with standard C++20
- Replaced OpenMP-based parallel full-domain evaluation with a standard-thread worker model
- Fixed the output domain to `uint64_t`
- Added C ABI bindings for Go `cgo`

## License

The adapted logic remains under Apache-2.0. See `LICENSE.txt`.
