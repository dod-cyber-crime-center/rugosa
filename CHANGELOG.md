# Changelog
All notable changes to this project will be documented in this file.

## [0.6.0] - 2022-12-02
- Support all instruction operands, both implied and explicit.
- Fix bug in ROL opcode implementation.
- Added `.function_arg_values` property to ProcessorContext.
- Added `.get_function_arg_values()` convenience function to Emulator.
- Updated `ProcessorContext.call_history` to also include the argument names.
- Added IDA and Ghidra plugin to provide a GUI for using the emulation utility. (See [documentation](./docs/EmulatorPlugin.md))
  - Please note: These plugins are currently in beta.


## [0.5.1] - 2022-10-05
- Fixed performance issue during emulation.
- Fixed missing `_heap_base` error when allocating memory.


## [0.5.0] - 2022-09-15
- Added ability to emulate functions calls. (See [documentation](./docs/CPUEmulation.md#emulating-function-calls))
- Added ability to execute full functions with `Emulator.execute_function()`.
- Added tracking of stdout in `ProcessorContext`.
- Added `printf` call hook.
- Changed `ProcessorContext.func_calls` to `ProcessorContext.call_history`. `func_calls` is now deprecated.
- Added ability to stream emulated memory using `context.memory.open()`. (See [documentation](./docs/CPUEmulation.md#memory-streaming))


## [0.4.0] - 2022-08-10

- `rugosa.emulation.memory.clear_cache()` has been moved to `rugosa.emulation.emulator.Emulator.clear_cache()` in
  order to fix a bug with `cache_clear()` not working when teleported.
- Improved `rugosa.iter_imports()` function to dedup results.
- Fixed bug in `rugosa.re.find_functions()`.
- Added ability to get and set `.calling_convention` and `.return_type` in emulated `FunctionSignature`.


## [0.3.0] - 2022-06-28

### Added
- Added `iter_import_calls()` and `iter_import_callers()` functions to better handle pivoting off import functions.
- Added support for tracking decrypted string with `rugosa.DecodedString`.
- Bugfixes to better support Ghidra backend.


## [0.2.0] - 2022-06-01

### Changed
- IDA: Greatly improved emulation performance by "teleporting" the `Emulator` instance into the IDA interpreter.

### Fixed
- *Emulation*
  - Fixed issues with windows constants in call hooks.
  - Fixed bugs in opcode calls.


## [0.1.1] - 2022-03-23

### Added
- *Emulation*
    - Added `PathAddBackslash` SHLWAPI hook

### Fixed
- *Emulation*
  - Mask off any CSIDL flags before resolving folder in `SHGetFolderPath`
- Fixed failure of tests due to ordering.


## 0.1.0 - 2022-02-04
- Initial release.
- Migrated the majority of Kordesii functionality to work with Dragodis.


[Unreleased]: https://github.com/dod-cyber-crime-center/rugosa/compare/0.6.0...HEAD
[0.6.0]: https://github.com/dod-cyber-crime-center/rugosa/compare/0.5.1...0.6.0
[0.5.1]: https://github.com/dod-cyber-crime-center/rugosa/compare/0.5.0...0.5.1
[0.5.0]: https://github.com/dod-cyber-crime-center/rugosa/compare/0.4.0...0.5.0
[0.4.0]: https://github.com/dod-cyber-crime-center/rugosa/compare/0.3.0...0.4.0
[0.3.0]: https://github.com/dod-cyber-crime-center/rugosa/compare/0.2.0...0.3.0
[0.2.0]: https://github.com/dod-cyber-crime-center/rugosa/compare/0.1.1...0.2.0
[0.1.1]: https://github.com/dod-cyber-crime-center/rugosa/compare/0.1.0...0.1.1
