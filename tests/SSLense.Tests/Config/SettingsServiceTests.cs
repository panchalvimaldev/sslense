using Moq;
using SSLense.Core.Config;
using Xunit;

namespace SSLense.Tests.Config;

public sealed class SettingsServiceTests
{
    [Fact]
    public async Task SaveGeneralAsync_PreservesNotificationsAndForcesStaging()
    {
        var notifications = new NotificationConfig { NotifyOnSuccess = true };
        AppConfig? saved = null;
        var store = new Mock<IConfigStore>(MockBehavior.Strict);
        store.Setup(value => value.LoadAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AppConfig { UseStaging = false, Notifications = notifications });
        store.Setup(value => value.SaveAsync(It.IsAny<AppConfig>(), It.IsAny<CancellationToken>()))
            .Callback<AppConfig, CancellationToken>((value, _) => saved = value)
            .Returns(Task.CompletedTask);
        var service = new SettingsService(store.Object);

        await service.SaveGeneralAsync("admin@example.com", 21);

        Assert.NotNull(saved);
        Assert.True(saved.UseStaging);
        Assert.Equal(21, saved.RenewalThresholdDays);
        Assert.Same(notifications, saved.Notifications);
    }
}
