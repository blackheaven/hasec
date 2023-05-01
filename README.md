# HλSec

(Pronounced `\o sɛk\`, french for *kept dry*, "*mis au sec*").

Security tools which will be used as a basis (yet liberal) of [HaskellFundation's advisory proposal](https://github.com/haskellfoundation/tech-proposals/blob/main/proposals/accepted/037-advisory-db.md).

## Design

* [hasec-core](blob/master/hasec-core)
  * Basic policy implementation
  * Define base types and parser/renderer
  * Aims to be embedded (hereafter CLI, cabal, stack, hackage, etc.)
* [hasec-cli](blob/master/hasec-cli)
  * Standalone CLI
  * Analyze project
  * Bootstrap advisory entry
  * Generate various formats (e.g. Github advisory format)
