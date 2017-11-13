# Malware Analysis Notes

## Static Analysis
- IDA failed analysis immediately
  - Looking at imports, importing `LoadLibraryA` and `GetProcAddress` - probably packed
  - Using PEiD, discovered malware was packed with UPX
  - Successfully unpacked malware
- Malware immediately calls `BroadcastSystemMessage(0, ?, 0, 0, 0)` - forcing some component to close?
  - Seg faults at `0x411808`

## More Information
- Generated the hash e1e1f806e3be776dfaf0f6cbae4d0a45 (of the executable, not the zip, though both are on the site)
- [Located file on VirusTotal](https://www.virustotal.com/en/file/da1488b16630790d0bf937d1d53e0edba13c4314b7b24c59ff5fbf27f026d989/analysis/)
- 
