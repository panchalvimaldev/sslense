using System.Windows;
using System.Windows.Media;
using Microsoft.Win32;

namespace SSLense.Gui.Themes;

/// <summary>
/// High contrast and larger text (docs/design/accessibility.md). Views use the brushes in DesignSystem.xaml only, so in
/// high contrast every one of them is replaced by a Windows system colour, chosen by what it is used for.
/// </summary>
public static class AccessibilityTheme
{
    public const double MinimumScale = 0.8;
    public const double MaximumScale = 2.5;

    /// <summary>Which system colour each brush becomes in high contrast.</summary>
    public static IReadOnlyDictionary<string, Func<Brush>> HighContrastBrushes { get; } = new Dictionary<string, Func<Brush>>
    {
        ["BrandBrush"] = () => SystemColors.HighlightBrush,
        ["BrandHoverBrush"] = () => SystemColors.HotTrackBrush,
        ["BrandSoftBrush"] = () => SystemColors.WindowBrush,
        ["CanvasBrush"] = () => SystemColors.WindowBrush,
        ["SurfaceBrush"] = () => SystemColors.WindowBrush,
        ["SubtleSurfaceBrush"] = () => SystemColors.WindowBrush,
        ["BorderBrush"] = () => SystemColors.WindowTextBrush,
        ["TextBrush"] = () => SystemColors.WindowTextBrush,
        ["MutedTextBrush"] = () => SystemColors.WindowTextBrush,
        ["SuccessBrush"] = () => SystemColors.WindowTextBrush,
        ["SuccessSoftBrush"] = () => SystemColors.WindowBrush,
        ["WarningBrush"] = () => SystemColors.WindowTextBrush,
        ["WarningStrongBrush"] = () => SystemColors.WindowTextBrush,
        ["WarningSoftBrush"] = () => SystemColors.WindowBrush,
        ["DangerBrush"] = () => SystemColors.WindowTextBrush,
        ["DangerSoftBrush"] = () => SystemColors.WindowBrush,
        ["SidebarBrush"] = () => SystemColors.WindowBrush,
        ["SidebarHoverBrush"] = () => SystemColors.HighlightBrush,
        ["OnBrandBrush"] = () => SystemColors.HighlightTextBrush,
        ["HoverBrush"] = () => SystemColors.HighlightBrush,
        ["BrandBorderBrush"] = () => SystemColors.WindowTextBrush,
        ["StrongBorderBrush"] = () => SystemColors.WindowTextBrush,
        ["MutedBorderBrush"] = () => SystemColors.WindowTextBrush,
        ["SubtleBorderBrush"] = () => SystemColors.WindowTextBrush,
        ["SuccessBorderBrush"] = () => SystemColors.WindowTextBrush,
        ["WarningBorderBrush"] = () => SystemColors.WindowTextBrush,
        ["WarningAccentBrush"] = () => SystemColors.WindowTextBrush,
        ["DangerBorderBrush"] = () => SystemColors.WindowTextBrush,
        ["StrongTextBrush"] = () => SystemColors.WindowTextBrush,
        ["OverlayBrush"] = () => SystemColors.WindowBrush
    };

    /// <summary>
    /// Replaces the theme's brushes before any window is created, because views take them as static resources. The
    /// styles in DesignSystem.xaml take them as dynamic resources, so they follow the replacement too; as static
    /// resources they kept the normal colours, which the combined test found. Turning high contrast on or off later
    /// takes effect at the next start.
    /// </summary>
    public static bool ApplyHighContrast(ResourceDictionary resources, bool highContrast)
    {
        if (!highContrast)
        {
            return false;
        }

        foreach (var (key, brush) in HighContrastBrushes)
        {
            resources[key] = brush();
        }

        return true;
    }

    /// <summary>Windows' "Make text bigger" setting (Settings › Accessibility › Text size), as a scale from 1.0 to 2.25.</summary>
    public static double ReadTextScale()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Accessibility");
            return key?.GetValue("TextScaleFactor") is int percent ? Clamp(percent / 100d) : 1d;
        }
        catch (Exception exception) when (exception is System.Security.SecurityException or UnauthorizedAccessException or System.IO.IOException)
        {
            return 1d;
        }
    }

    public static double Clamp(double scale) => Math.Round(Math.Clamp(scale, MinimumScale, MaximumScale), 2);
}
