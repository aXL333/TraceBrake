# TraceBrake rename and compatibility contract

Foreman Agent Safety is now **TraceBrake**. This is a product rename, not a new project or a rewrite of its
history. The OpenAI Build Week submission, immutable tags, demo and dated audit material keep the original name.

## What changes

- The Windows application, installer, shortcuts, startup entry, browser extensions, website and current
  documentation display **TraceBrake**.
- The primary Windows executable is `TraceBrake.exe`.
- New installations use `%LocalAppData%\Programs\TraceBrake` for program files and
  `%LocalAppData%\TraceBrake` for mutable state.
- New release artefacts use the `TraceBrake-Setup-<version>.exe` name.

## Existing installation migration

The Inno Setup `AppId` and single-instance mutex remain stable. An installer upgrade therefore replaces the
existing product rather than creating a second installation. On first TraceBrake launch, while the shared mutex
proves no older instance is running, the application moves the complete `%LocalAppData%\Foreman` directory to
`%LocalAppData%\TraceBrake` as one directory operation. That keeps sealed settings, recovery snapshots, the MCP
install secret, vault material, profiles and event-log chain in one lineage.

TraceBrake never merges two data roots or overwrites one with the other. If both roots already exist it uses the
TraceBrake root, leaves the Foreman root untouched and raises a visible migration alert. If the move fails it
continues from the legacy root for that launch and reports the failure. A reparse-point legacy root is refused.

## Intentionally stable legacy identifiers

These names are compatibility or security contracts and remain unchanged for this migration release:

- internal .NET namespaces, project names and helper executable names (`Foreman.*`);
- the Guardian service, pipe, Program Files/ProgramData layout and administrator-owned registry anchor;
- the single-instance mutex;
- the Windows Event Log source, so lifecycle anchors and SIEM filters keep one continuous channel;
- existing `foreman` MCP configuration keys, `FOREMAN_MCP_*` environment variables and marked AGENTS.md blocks;
- the installed browser-extension subdirectory name, so an upgraded unpacked Chrome extension does not lose its
  source path;
- repository URLs until the GitHub repository itself is renamed or redirected.

These retained identifiers do not create a second product identity. Current UI and documentation label them as
legacy-compatible where an operator might encounter them.

## Packaging model

TraceBrake remains an unpackaged, per-user WPF application delivered by Inno Setup. It does not use MSIX. The
optional Guardian remains the only LocalSystem component and keeps its existing authenticated service boundary.
