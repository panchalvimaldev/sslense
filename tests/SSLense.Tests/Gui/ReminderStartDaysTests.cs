using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SSLense.Core.Acme;
using SSLense.Core.Config;
using SSLense.Core.DnsValidation;
using SSLense.Core.Notifications;
using SSLense.Core.Reminders;
using SSLense.Core.WindowsServices;
using SSLense.Gui.ViewModels;
using Xunit;

namespace SSLense.Tests.Gui;

/// <summary>A long "Start reminding" setting is explained, and the app asks before saving it.</summary>
public sealed class ReminderStartDaysTests
{
    private readonly Mock<IReminderService> _reminders = new();
    private readonly List<string> _questions = [];

    [Theory]
    [InlineData(1)]
    [InlineData(30)]
    [InlineData(ReminderConfig.LongStartDays)]
    public void UpToNinetyDays_HasNoWarning(int days) =>
        Assert.Null(new ReminderConfig { StartDays = days }.LongStartWarning);

    [Fact]
    public void AboveNinetyDays_SaysHowMuchOfAYearItCovers()
    {
        var warning = new ReminderConfig { StartDays = 173 }.LongStartWarning;

        Assert.NotNull(warning);
        Assert.Contains("173 days before expiry", warning, StringComparison.Ordinal);
        Assert.Contains("about 6 months", warning, StringComparison.Ordinal);
        Assert.Contains("30 to 60 days", warning, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Saving_ALongStart_AsksFirst_AndSavesNothingWhenTheAnswerIsNo()
    {
        var settings = Settings(answer: false);
        settings.ReminderStartDays = 173;

        Assert.NotNull(settings.LongStartWarning);
        await settings.SaveRemindersCommand.ExecuteAsync(null);

        Assert.Contains("Save 173 days anyway?", Assert.Single(_questions), StringComparison.Ordinal);
        _reminders.Verify(value => value.SaveSettingsAsync(It.IsAny<ReminderConfig>(), It.IsAny<CancellationToken>()), Times.Never);
        Assert.Equal("Reminder settings not saved.", settings.ResultMessage);
    }

    [Fact]
    public async Task Saving_ALongStart_SavesItWhenTheAnswerIsYes()
    {
        var settings = Settings(answer: true);
        settings.ReminderStartDays = 120;

        await settings.SaveRemindersCommand.ExecuteAsync(null);

        Assert.Single(_questions);
        _reminders.Verify(value => value.SaveSettingsAsync(It.Is<ReminderConfig>(config => config.StartDays == 120), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task Saving_ANormalStart_DoesNotAsk()
    {
        var settings = Settings(answer: false);
        settings.ReminderStartDays = 45;

        Assert.Null(settings.LongStartWarning);
        await settings.SaveRemindersCommand.ExecuteAsync(null);

        Assert.Empty(_questions);
        _reminders.Verify(value => value.SaveSettingsAsync(It.Is<ReminderConfig>(config => config.StartDays == 45), It.IsAny<CancellationToken>()), Times.Once);
    }

    private SettingsViewModel Settings(bool answer)
    {
        var settings = new SettingsViewModel(
            Mock.Of<ISettingsService>(),
            Mock.Of<INotificationSettingsService>(),
            Mock.Of<INotifier>(),
            Mock.Of<IWindowsServiceManager>(),
            _reminders.Object,
            Mock.Of<IDnsProviderService>(),
            Mock.Of<ICertificateAuthorityService>(value => value.Presets == CertificateAuthorities.Presets),
            NullLogger<SettingsViewModel>.Instance);
        settings.Confirm = question =>
        {
            _questions.Add(question);
            return answer;
        };
        return settings;
    }
}
