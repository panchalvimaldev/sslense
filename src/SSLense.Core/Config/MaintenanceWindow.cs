using SSLense.Core.Errors;

namespace SSLense.Core.Config;

/// <summary>
/// When automatic renewals may run, in server time (docs/design/maintenance-windows.md). A renewal that is due waits
/// for the window, but never so long that the certificate could expire: within the safety margin before expiry it
/// renews at once. Renewals started by an administrator always run at once.
/// </summary>
/// <param name="Days">The days a window starts on.</param>
/// <param name="StartHour">0 to 23: the hour the window opens.</param>
/// <param name="EndHour">0 to 23: the hour it closes. Earlier than <paramref name="StartHour"/> means the next day, as 22 to 4.</param>
public sealed record MaintenanceWindow(IReadOnlyList<DayOfWeek> Days, int StartHour, int EndHour)
{
    /// <summary>A renewal never waits for a window once it is this close to expiry: 2 days, or a tenth of the lifetime.</summary>
    public static TimeSpan SafetyMargin(ManagedCertificate certificate) =>
        TimeSpan.FromTicks(Math.Max(TimeSpan.FromDays(2).Ticks, (certificate.NotAfter - certificate.NotBefore).Ticks / 10));

    /// <summary>Refuses a window that could never open.</summary>
    public void Validate()
    {
        if (Days is null || Days.Count == 0)
        {
            throw new ArgumentException(ErrorCodes.MaintenanceWindowInvalid.Format("Choose at least one day for the maintenance window."));
        }

        if (StartHour is < 0 or > 23 || EndHour is < 0 or > 23)
        {
            throw new ArgumentException(ErrorCodes.MaintenanceWindowInvalid.Format("The maintenance window's hours must be from 0 to 23."));
        }

        if (StartHour == EndHour)
        {
            throw new ArgumentException(ErrorCodes.MaintenanceWindowInvalid.Format("The maintenance window must end at another hour than it starts."));
        }
    }

    /// <summary>Whether the window is open at <paramref name="now"/>, in <paramref name="zone"/>.</summary>
    public bool IsOpen(DateTimeOffset now, TimeZoneInfo zone)
    {
        var local = TimeZoneInfo.ConvertTime(now, zone);
        // A window that crosses midnight belongs to the day it started on.
        foreach (var start in Starts(local.Date.AddDays(-1), 2))
        {
            if (local.DateTime >= start && local.DateTime < start.AddHours(Length))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>When the window next opens after <paramref name="now"/>, in UTC.</summary>
    public DateTimeOffset NextOpening(DateTimeOffset now, TimeZoneInfo zone)
    {
        var local = TimeZoneInfo.ConvertTime(now, zone);
        var next = Starts(local.Date, 8).First(start => start > local.DateTime);
        return new DateTimeOffset(next, zone.GetUtcOffset(next)).ToUniversalTime();
    }

    /// <summary>
    /// Whether a due scheduled renewal waits for the window: null to renew now, or why it waits and until when.
    /// </summary>
    public (DateTimeOffset Opens, string Reason)? Wait(ManagedCertificate certificate, DateTimeOffset now, TimeZoneInfo zone)
    {
        if (IsOpen(now, zone))
        {
            return null;
        }

        var opens = NextOpening(now, zone);
        var lastSafe = certificate.NotAfter - SafetyMargin(certificate);
        return opens > lastSafe
            ? null
            : (opens, $"Waiting for the maintenance window, which opens {TimeZoneInfo.ConvertTime(opens, zone):ddd yyyy-MM-dd HH:mm} server time.");
    }

    /// <summary>For people: "Mon, Tue 01:00 to 05:00 (server time)".</summary>
    public string Describe() =>
        $"{string.Join(", ", Days.OrderBy(day => ((int)day + 6) % 7).Select(day => day.ToString()[..3]))} " +
        $"{StartHour:00}:00 to {EndHour:00}:00{(EndHour < StartHour ? " the next day" : string.Empty)} (server time)";

    private int Length => (EndHour - StartHour + 24) % 24;

    private IEnumerable<DateTime> Starts(DateTime fromDate, int days)
    {
        for (var day = 0; day < days; day++)
        {
            var date = fromDate.AddDays(day);
            if (Days.Contains(date.DayOfWeek))
            {
                yield return date.AddHours(StartHour);
            }
        }
    }
}
