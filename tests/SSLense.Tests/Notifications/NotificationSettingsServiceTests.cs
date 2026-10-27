using System.Text;
using Moq;
using SSLense.Core.Acme;
using SSLense.Core.Config;
using SSLense.Core.Notifications;
using Xunit;

namespace SSLense.Tests.Notifications;

public sealed class NotificationSettingsServiceTests
{
    [Fact]
    public async Task ConfigureAsync_ProtectsPasswordAndWebhookBeforeSaving()
    {
        AppConfig? saved = null;
        var configStore = new Mock<IConfigStore>(MockBehavior.Strict);
        configStore.Setup(value => value.LoadAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AppConfig());
        configStore.Setup(value => value.SaveAsync(It.IsAny<AppConfig>(), It.IsAny<CancellationToken>()))
            .Callback<AppConfig, CancellationToken>((config, _) => saved = config)
            .Returns(Task.CompletedTask);
        var protector = new Mock<ISecretProtector>(MockBehavior.Strict);
        protector.Setup(value => value.Protect(It.IsAny<byte[]>()))
            .Returns<byte[]>(plaintext => Encoding.UTF8.GetBytes($"protected:{Encoding.UTF8.GetString(plaintext)}"));
        var service = new NotificationSettingsService(configStore.Object, protector.Object);

        await service.ConfigureAsync(new NotificationSettingsRequest(
            new SmtpSettingsRequest(
                "smtp.example.com", 587, true, "user", "super-secret", "from@example.com", "to@example.com"),
            "https://hooks.example.com/secret-token",
            true));

        Assert.NotNull(saved);
        Assert.True(saved.Notifications.NotifyOnSuccess);
        Assert.NotEqual("super-secret", saved.Notifications.Smtp!.ProtectedPassword);
        Assert.DoesNotContain("secret-token", saved.Notifications.Webhook!.ProtectedUrl, StringComparison.Ordinal);
        protector.Verify(value => value.Protect(It.IsAny<byte[]>()), Times.Exactly(2));
    }
}
