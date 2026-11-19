using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using SSLense.Core.Errors;

namespace SSLense.Gui.Controls;

/// <summary>
/// An error message whose code, such as SSL1003, is a link to its entry in docs/errors.md
/// (docs/design/error-codes.md). A message without a code is shown as it is.
/// </summary>
public sealed class ErrorText : TextBlock
{
    public static readonly DependencyProperty MessageProperty = DependencyProperty.Register(
        nameof(Message), typeof(string), typeof(ErrorText), new PropertyMetadata(null, (target, _) => ((ErrorText)target).Render()));

    public string? Message
    {
        get => (string?)GetValue(MessageProperty);
        set => SetValue(MessageProperty, value);
    }

    private void Render()
    {
        Inlines.Clear();
        var message = Message ?? string.Empty;
        // Inlines do not set Text, so styles that hide an empty TextBlock cannot see this one; it hides itself.
        Visibility = message.Length == 0 ? Visibility.Collapsed : Visibility.Visible;
        if (ErrorCode.Of(message) is not { } code)
        {
            Inlines.Add(new Run(message));
            return;
        }

        var link = new Hyperlink(new Run(code.Code))
        {
            NavigateUri = code.Link,
            ToolTip = $"{code.Title}: what it means and what to do"
        };
        System.Windows.Automation.AutomationProperties.SetName(link, $"Error {code.Code}: {code.Title}. Opens its explanation.");
        link.RequestNavigate += (_, args) =>
        {
            Process.Start(new ProcessStartInfo(args.Uri.AbsoluteUri) { UseShellExecute = true });
            args.Handled = true;
        };
        Inlines.Add(link);
        Inlines.Add(new Run(message[code.Code.Length..]));
    }
}
