using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Media;
using SSLense.Gui.Themes;
using Xunit;

namespace SSLense.Tests.Gui;

/// <summary>High contrast and larger text (docs/design/accessibility.md).</summary>
public sealed class AccessibilityThemeTests
{
    [Fact]
    public void EveryThemeBrush_HasAHighContrastColour_AndHighContrastReplacesThemAll()
    {
        GuiThread.Run(() =>
        {
            var theme = new ResourceDictionary { Source = new Uri("pack://application:,,,/SSLense.Gui;component/Themes/DesignSystem.xaml") };
            var brushes = theme.Keys.OfType<string>().Where(key => theme[key] is SolidColorBrush).ToArray();

            Assert.Empty(brushes.Except(AccessibilityTheme.HighContrastBrushes.Keys));

            var resources = new ResourceDictionary();
            Assert.False(AccessibilityTheme.ApplyHighContrast(resources, highContrast: false));
            Assert.Empty(resources.Keys);
            Assert.True(AccessibilityTheme.ApplyHighContrast(resources, highContrast: true));
            Assert.Same(SystemColors.WindowTextBrush, resources["TextBrush"]);
        });
    }

    /// <summary>
    /// Found in the combined test: in high contrast the styles kept their normal colours, because they took the brushes
    /// when the theme loaded. Cards stayed white under white text, and the title stayed dark blue on black.
    /// </summary>
    [Fact]
    public void InHighContrast_StyledControlsShowTheSystemColours()
    {
        GuiThread.Run(() =>
        {
            var card = new System.Windows.Controls.Border { Style = (Style)Application.Current.FindResource("Card") };
            var banner = new System.Windows.Controls.Border { Style = (Style)Application.Current.FindResource("SuccessBanner") };
            var title = new System.Windows.Controls.TextBlock { Style = (Style)Application.Current.FindResource("DetailTitle") };
            var box = new System.Windows.Controls.TextBox();
            var panel = new System.Windows.Controls.StackPanel { Children = { card, banner, title, box } };
            AccessibilityTheme.ApplyHighContrast(panel.Resources, highContrast: true);
            var window = new Window { Content = panel, Left = -10000, Top = -10000, Width = 200, Height = 200, ShowActivated = false, ShowInTaskbar = false };
            try
            {
                window.Show();

                Assert.Same(SystemColors.WindowBrush, card.Background);
                Assert.Same(SystemColors.WindowTextBrush, card.BorderBrush);
                Assert.Same(SystemColors.WindowBrush, banner.Background);
                Assert.Same(SystemColors.WindowTextBrush, title.Foreground);
                Assert.Same(SystemColors.WindowBrush, box.Background);
                Assert.Same(SystemColors.WindowTextBrush, box.Foreground);
            }
            finally
            {
                window.Close();
            }
        });
    }

    /// <summary>A colour written into a view would stay the same in high contrast, so views use the theme's brushes only.</summary>
    [Fact]
    public void NoViewWritesAColourOfItsOwn()
    {
        var root = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", ".."));
        var gui = Path.Combine(root, "src", "SSLense.Gui");
        var offenders = Directory.EnumerateFiles(gui, "*.xaml", SearchOption.AllDirectories)
            .Where(path => !path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal) &&
                           !path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .SelectMany(path => File.ReadLines(path).Select((line, index) => (Path.GetFileName(path), index + 1, line)))
            .Where(item => !item.line.Contains("x:Key=", StringComparison.Ordinal) &&
                           Regex.IsMatch(item.line, @"(Background|BorderBrush|Foreground|Fill|Stroke|Value)=""(#[0-9A-Fa-f]{6,8}|White|Black)"""))
            .Select(item => $"{item.Item1}:{item.Item2}")
            .ToArray();

        Assert.Empty(offenders);
    }

    [Theory]
    [InlineData(1.5, 1.5)]
    [InlineData(0.1, AccessibilityTheme.MinimumScale)]
    [InlineData(9, AccessibilityTheme.MaximumScale)]
    public void TheZoom_StaysWithinLimits(double requested, double expected)
    {
        Assert.Equal(expected, AccessibilityTheme.Clamp(requested));
    }
}
