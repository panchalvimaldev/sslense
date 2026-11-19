using System.Windows;
using System.Windows.Documents;
using SSLense.Gui.Controls;
using Xunit;

namespace SSLense.Tests.Gui;

/// <summary>An error's code is a link to its explanation (docs/design/error-codes.md).</summary>
public sealed class ErrorTextTests
{
    [Fact]
    public void AMessageWithACode_LinksTheCode_AndKeepsTheWords() => GuiThread.Run(() =>
    {
        var text = new ErrorText { Message = "SSL1001: IIS site 'Shop' was not found." };

        var link = Assert.IsType<Hyperlink>(text.Inlines.FirstInline);
        Assert.Equal("SSL1001", Assert.IsType<Run>(link.Inlines.FirstInline).Text);
        Assert.EndsWith("/docs/errors.md#ssl1001", link.NavigateUri.ToString(), StringComparison.Ordinal);
        Assert.Equal(": IIS site 'Shop' was not found.", Assert.IsType<Run>(link.NextInline).Text);
        Assert.Equal(Visibility.Visible, text.Visibility);
    });

    [Fact]
    public void AMessageWithoutACode_IsPlainText_AndNoMessageHidesIt() => GuiThread.Run(() =>
    {
        var text = new ErrorText { Message = "Select a certificate authority to test." };
        Assert.IsType<Run>(text.Inlines.FirstInline);

        text.Message = null;
        Assert.Equal(Visibility.Collapsed, text.Visibility);
    });
}
