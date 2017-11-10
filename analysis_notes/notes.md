# Malware Analysis Notes

## Static Analysis
- IDA failed analysis immediately
  - Looking at imports, importing `LoadLibraryA` and `GetProcAddress` - probably packed
  - Using PEiD, discovered malware was packed with UPX
  - Successfully unpacked malware
- Malware immediately calls `BroadcastSystemMessage(0, ?, 0, 0, 0)` - forcing some component to close?
  - Seg faults at `0x411808`
