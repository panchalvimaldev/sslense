using SSLense.Core.Validation;

namespace SSLense.Gui.ViewModels;

public sealed class PreflightCheckViewModel(PreflightCheck check)
{
    public string Name { get; } = check.Name;

    public bool Succeeded { get; } = check.Succeeded;

    public string Result => check.Succeeded ? "PASS" : "FAIL";

    public string Message { get; } = check.Message;
}
