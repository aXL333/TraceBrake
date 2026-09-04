## Summary

-

## Verification

- [ ] `dotnet build .\Foreman.slnx -c Release`
- [ ] `powershell -NoProfile -File .\scripts\Invoke-DotNetTests.ps1 -Configuration Release -NoBuild`

## Safety / Privacy Notes

- [ ] This change does not expose tokens, command lines, or process data outside the local machine.
- [ ] Detection-rule changes include tests and safe framing.
- [ ] MCP/tool-surface changes are documented.
