# Contributing to SSLense

Thanks for helping. Bug reports, documentation fixes, tests, and code are all welcome.

## Before you start

- **Security problems:** do not open a public issue; follow [SECURITY.md](SECURITY.md).
- **Larger changes:** open an issue first to agree on the approach, especially for anything touching renewal, IIS bindings, the certificate store, or secrets.
- Read [PROJECT_SPEC.md](PROJECT_SPEC.md) and [ROADMAP.md](ROADMAP.md) for the design and priorities.

## Building and testing

Requirements: Windows, the .NET 10 SDK (see `global.json`), and IIS with *IIS Management Scripts and Tools* for manual testing.

```powershell
dotnet build .\SSLense.sln
dotnet test .\SSLense.sln
```

Both must pass with no warnings; warnings are treated as errors. Building the MSI is optional and described in the README.

## Ground rules

- **Use Let's Encrypt staging only.** Never run tests or experiments against the production endpoint. Production rate limits are shared and easy to exhaust.
- **Keep the GUI and CLI thin.** Business logic belongs in `SSLense.Core`, behind interfaces that tests can mock. Every operation should work identically from the GUI and the CLI.
- **Never log secrets:** private keys, PFX passwords, ACME account keys, SMTP passwords, or webhook URLs.
- **Never leave a site without a working binding.** Changes to issuance, renewal, or binding code must preserve the existing certificate until the replacement is verified, and need tests for the failure paths.
- **Add tests** for new behaviour and for every bug fix.
- **Dependencies:** discuss new NuGet packages in an issue first. They must use a license compatible with Apache-2.0.
- Match the surrounding code's style, naming, and comment density.

## Sign your commits (DCO)

SSLense uses the [Developer Certificate of Origin](https://developercertificate.org/). By adding a `Signed-off-by` line to each commit, you certify that you wrote the change or have the right to submit it under the project's license:

```powershell
git commit -s -m "Describe the change"
```

This adds `Signed-off-by: Your Name <your.email@example.com>`, using your Git name and email.

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).
