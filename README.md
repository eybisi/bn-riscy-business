# bn-riscy-business

An architecture plug-in that allows binary ninja to load [Riscy-Business](https://github.com/thesecretclub/riscy-business/tree/master) payload binaries and see decrypted rv64i instructions.

This plugin is fork of [bn-riscv](https://github.com/uni-due-syssec/bn-riscv). 

For the analysis of riscy-business you can read [Analysis of riscy-business payloads](xx)

## Installation

First, you will need an installation of [capstone](https://github.com/aquynh/capstone) that supports RISC-V.

```
pip install --user 'capstone'
```

Then drop this repository into your plugins directory manually. Note that you should use it from master if possible, releases are somewhat rare.