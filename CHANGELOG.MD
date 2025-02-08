#### 0.3
---
-Various bug fixes.

-Added support for PiHole, Open Media Vault, and Debian.

#### 0.4
---
-Consolidated all built-in log file types to use `built_in_process_log()` for simplification (Breaking change).
Named function calls from version < 0.4 will need to be replaced with this function from the built_ins module.

#### 0.5
---
-Improved exception handling for additional column functions

-Added support for PFSense (syslog format)

-Addition of type hints matching docstrings