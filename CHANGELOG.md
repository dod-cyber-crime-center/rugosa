# Changelog
All notable changes to this project will be documented in this file.


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


[Unreleased]: https://github.com/dod-cyber-crime-center/rugosa/compare/0.3.0...HEAD
[0.3.0]: https://github.com/dod-cyber-crime-center/rugosa/compare/0.2.0...0.3.0
[0.2.0]: https://github.com/dod-cyber-crime-center/rugosa/compare/0.1.1...0.2.0
[0.1.1]: https://github.com/dod-cyber-crime-center/rugosa/compare/0.1.0...0.1.1
