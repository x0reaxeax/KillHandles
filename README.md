# KillHandles

Attempts to detect all handles owned by target PID and close them via `NtDuplicateObject` + `DUPLICATE_CLOSE_SOURCE` flag.
