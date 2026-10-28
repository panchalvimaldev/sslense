# AGENTS.md

## Project
Windows tool (C# / .NET 10 LTS) that issues and renews Let's Encrypt certificates for IIS.
Full requirements are in PROJECT_SPEC.md. Read it before starting any task.

## Rules
- Work one phase at a time. Finish, summarize how to run it, then stop and wait.
- GUI and CLI are thin wrappers over SSLense.Core. No business logic in them.
- Use Let's Encrypt STAGING only. Never use production unless I say so.
- Never log private keys, PFX passwords, or the ACME account key.
- Ask before adding NuGet packages not listed in PROJECT_SPEC.md.
- Run `dotnet build` and `dotnet test` before saying a phase is done.
