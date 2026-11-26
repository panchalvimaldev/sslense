using Moq;
using SSLense.Core.Acme;
using SSLense.Core.Config;
using SSLense.Core.Errors;
using SSLense.Core.Notifications;
using System.Net;
using System.Text;
using System.Text.Json;
using Xunit;

namespace SSLense.Tests.Notifications;

/// <summary>Signed webhook payloads (docs/design/signed-webhooks.md).</summary>
public sealed class SignedWebhookTests
{
    private static readonly NotificationMessage Message = new(NotificationKind.RenewalFailure, "Renewal failed: Shop", "It failed.");

    [Fact]
    public async Task ASignedPayload_CarriesATimestampAndAnHmacOverTimestampAndBody()
    {
        using var request = ChatSender.CreateRequest(ChatFormat.Generic, new Uri("https://hooks.example.com/in"), Message, "shared-secret");

        var timestamp = Assert.Single(request.Headers.GetValues(ChatSender.TimestampHeader));
        var signature = Assert.Single(request.Headers.GetValues(ChatSender.SignatureHeader));
        var body = await request.Content!.ReadAsStringAsync();
        var expected = "sha256=" + Convert.ToHexStringLower(System.Security.Cryptography.HMACSHA256.HashData(
            Encoding.UTF8.GetBytes("shared-secret"), Encoding.UTF8.GetBytes($"{timestamp}.{body}")));
        Assert.Equal(expected, signature);
        Assert.True(Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeSeconds() - long.Parse(timestamp, System.Globalization.CultureInfo.InvariantCulture)) < 60);
        Assert.Equal("Renewal failed: Shop", JsonDocument.Parse(body).RootElement.GetProperty("subject").GetString());
    }

    [Fact]
    public void AnUnsignedPayload_HasNoSignature()
    {
        using var request = ChatSender.CreateRequest(ChatFormat.Generic, new Uri("https://hooks.example.com/in"), Message);

        Assert.False(request.Headers.Contains(ChatSender.SignatureHeader));
    }

    [Fact]
    public async Task AddingASignedWebhook_ReturnsTheSecretOnce_AndKeepsItProtected()
    {
        var (service, saved) = Settings();

        var secret = await service.AddChatAsync(new ChatSettingsRequest(ChatFormat.Generic, "https://hooks.example.com/in", "Ops", Sign: true));

        Assert.NotNull(secret);
        Assert.True(secret.Length >= 40);
        var chat = Assert.Single(saved().Notifications.Chat);
        Assert.Equal($"protected:{secret}", Encoding.UTF8.GetString(Convert.FromBase64String(chat.ProtectedSigningSecret!)));
        Assert.True(Assert.Single((await service.GetOverviewAsync()).Chat).Signed);
    }

    [Fact]
    public async Task OnlyGenericWebhooks_AreSigned()
    {
        var (service, _) = Settings();

        await Assert.ThrowsAsync<ArgumentException>(() =>
            service.AddChatAsync(new ChatSettingsRequest(ChatFormat.Slack, "https://hooks.slack.com/services/x", Sign: true)));
    }

    [Fact]
    public async Task TheNotifier_SignsWithTheSavedSecret()
    {
        var notifications = new NotificationConfig
        {
            EventLogEnabled = false,
            Chat = [new ChatNotificationConfig(ChatFormat.Generic, Plain("https://hooks.example.com/in"), null, Plain("shared-secret"))]
        };
        var chat = new Mock<IChatSender>(MockBehavior.Strict);
        chat.Setup(value => value.SendSignedAsync(new Uri("https://hooks.example.com/in"), It.IsAny<NotificationMessage>(), "shared-secret", It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        var results = await Notifier(notifications, chat: chat.Object).TestAsync();

        Assert.True(Assert.Single(results).Succeeded);
        chat.VerifyAll();
    }

    private static string Plain(string value) => Convert.ToBase64String(Encoding.UTF8.GetBytes(value));

    private static Notifier Notifier(NotificationConfig notifications, IChatSender chat)
    {
        var configStore = new Mock<IConfigStore>();
        configStore.Setup(value => value.LoadAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new AppConfig { Notifications = notifications });
        var protector = new Mock<ISecretProtector>();
        protector.Setup(value => value.Unprotect(It.IsAny<byte[]>())).Returns<byte[]>(bytes => (byte[])bytes.Clone());
        return new Notifier(configStore.Object, protector.Object, Mock.Of<IEmailSender>(), chat, Mock.Of<IEventLogWriter>(), new HttpClient());
    }

    private static (NotificationSettingsService Service, Func<AppConfig> Saved) Settings()
    {
        var current = new AppConfig();
        var configStore = new Mock<IConfigStore>();
        configStore.Setup(value => value.LoadAsync(It.IsAny<CancellationToken>())).ReturnsAsync(() => current);
        configStore.Setup(value => value.SaveAsync(It.IsAny<AppConfig>(), It.IsAny<CancellationToken>()))
            .Callback<AppConfig, CancellationToken>((config, _) => current = config)
            .Returns(Task.CompletedTask);
        var protector = new Mock<ISecretProtector>();
        protector.Setup(value => value.Protect(It.IsAny<byte[]>()))
            .Returns<byte[]>(plaintext => Encoding.UTF8.GetBytes($"protected:{Encoding.UTF8.GetString(plaintext)}"));
        return (new NotificationSettingsService(configStore.Object, protector.Object), () => current);
    }
}
