using SSLense.Core.Config;
using Xunit;

namespace SSLense.Tests.Config;

/// <summary>When automatic renewals may run (docs/design/maintenance-windows.md). Times are in UTC here.</summary>
public sealed class MaintenanceWindowTests
{
    private static readonly TimeZoneInfo Utc = TimeZoneInfo.Utc;
    private static readonly MaintenanceWindow Weeknights = new([DayOfWeek.Monday, DayOfWeek.Tuesday, DayOfWeek.Wednesday, DayOfWeek.Thursday, DayOfWeek.Friday], 1, 5);
    private static readonly MaintenanceWindow SaturdayNight = new([DayOfWeek.Saturday], 22, 4);

    // November 2026: the 16th is a Monday, the 20th a Friday, the 21st a Saturday.
    private static DateTimeOffset At(int day, int hour, int minute = 0) => new(2026, 11, day, hour, minute, 0, TimeSpan.Zero);

    [Theory]
    [InlineData(16, 1, true)]
    [InlineData(16, 4, true)]
    [InlineData(16, 5, false)]
    [InlineData(16, 0, false)]
    [InlineData(21, 2, false)]
    public void AWindowOnWeekdays_IsOpenOnlyInItsHours(int day, int hour, bool open) =>
        Assert.Equal(open, Weeknights.IsOpen(At(day, hour), Utc));

    [Theory]
    [InlineData(21, 22, true)]
    [InlineData(22, 3, true)]
    [InlineData(22, 4, false)]
    [InlineData(21, 21, false)]
    [InlineData(22, 23, false)]
    public void AWindowAcrossMidnight_BelongsToTheDayItStarts(int day, int hour, bool open) =>
        Assert.Equal(open, SaturdayNight.IsOpen(At(day, hour), Utc));

    [Fact]
    public void TheNextOpening_SkipsDaysWithoutAWindow()
    {
        Assert.Equal(At(23, 1), Weeknights.NextOpening(At(20, 6), Utc));
        Assert.Equal(At(17, 1), Weeknights.NextOpening(At(16, 1, 30), Utc));
        Assert.Equal(At(21, 22), SaturdayNight.NextOpening(At(16, 12), Utc));
    }

    [Fact]
    public void ADueRenewal_WaitsForTheWindow_UnlessItIsCloseToExpiry()
    {
        var now = At(20, 6);
        var plentyLeft = Certificate(now.AddDays(-60), now.AddDays(30));
        var almostExpired = Certificate(now.AddDays(-89), now.AddDays(1));

        var wait = Weeknights.Wait(plentyLeft, now, Utc);
        Assert.NotNull(wait);
        Assert.Equal(At(23, 1), wait.Value.Opens);
        Assert.Contains("Mon 2026-11-23 01:00", wait.Value.Reason, StringComparison.Ordinal);

        Assert.Null(Weeknights.Wait(almostExpired, now, Utc));
        Assert.Null(Weeknights.Wait(plentyLeft, At(23, 2), Utc));
    }

    [Fact]
    public void AShortLivedCertificate_NeverWaitsPastItsMargin()
    {
        // Six days of life: the margin is 2 days, so a window three days away is too late.
        var now = At(20, 6);
        var shortLived = Certificate(now.AddDays(-2), now.AddDays(4));

        Assert.Equal(TimeSpan.FromDays(2), MaintenanceWindow.SafetyMargin(shortLived));
        Assert.Null(new MaintenanceWindow([DayOfWeek.Monday], 1, 5).Wait(shortLived, now, Utc));
        Assert.Equal(TimeSpan.FromDays(9), MaintenanceWindow.SafetyMargin(Certificate(now, now.AddDays(90))));
    }

    [Theory]
    [InlineData(new DayOfWeek[0], 1, 5)]
    [InlineData(new[] { DayOfWeek.Monday }, 3, 3)]
    [InlineData(new[] { DayOfWeek.Monday }, 1, 24)]
    public void AWindowThatCouldNeverOpen_IsRefused(DayOfWeek[] days, int start, int end)
    {
        var exception = Assert.Throws<ArgumentException>(() => new MaintenanceWindow(days, start, end).Validate());
        Assert.StartsWith("SSL5022: ", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ItDescribesItselfForPeople()
    {
        Assert.Equal("Mon, Tue, Wed, Thu, Fri 01:00 to 05:00 (server time)", Weeknights.Describe());
        Assert.Equal("Sat 22:00 to 04:00 the next day (server time)", SaturdayNight.Describe());
    }

    private static ManagedCertificate Certificate(DateTimeOffset notBefore, DateTimeOffset notAfter) =>
        new("Shop", ["shop.example.com"], "ops@example.com", "AA", notBefore, notAfter);
}
