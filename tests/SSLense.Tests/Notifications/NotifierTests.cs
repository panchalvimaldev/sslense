using System.Text;
using Moq;
using SSLense.Core.Acme;
using SSLense.Core.Config;
using SSLense.Core.Notifications;
using Xunit;

namespace SSLense.Tests.Notifications;

public sealed class NotifierTests
{
    [Fact]
    public async Task NotifyAsync_ConfiguredChannels_DecryptsAndSendsToBoth()
    {
        var smtpPassword = Convert.ToBase64String(Encoding.UTF8.GetBytes("encrypted-password"));
        var webhookUrl = Convert.ToBase64String(Encoding.UTF8.GetBytes("encrypted-webhook"));
        var configStore = MockConfig(new NotificationConfig
        {
            Smtp = new SmtpNotificationConfig(
                "smtp.example.com", 587, true, "user", smtpPassword, "from@example.com", "to@example.com"),
            Webhook = new WebhookNotificationConfig(webhookUrl)
        });
        var protector = new Mock<ISecretProtector>(MockBehavior.Strict);
        protector.Setup(value => value.Unprotect(It.Is<byte[]>(bytes =>
                Encoding.UTF8.GetString(bytes) == "encrypted-password")))
            .Returns(Encoding.UTF8.GetBytes("plain-password"));
        protector.Setup(value => value.Unprotect(It.Is<byte[]>(bytes =>
                Encoding.UTF8.GetString(bytes) == "encrypted-webhook")))
            .Returns(Encoding.UTF8.GetBytes("https://hooks.example.com/value"));
        var email = new Mock<IEmailSender>(MockBehavior.Strict);
        email.Setup(value => value.SendAsync(
                It.Is<SmtpDeliverySettings>(settings => settings.Password == "plain-password"),
                It.IsAny<NotificationMessage>(),
                It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        var webhook = new Mock<IWebhookSender>(MockBehavior.Strict);
        webhook.Setup(value => value.SendAsync(
                new Uri("https://hooks.example.com/value"),
                It.IsAny<NotificationMessage>(),
                It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        var notifier = new Notifier(configStore.Object, protector.Object, email.Object, webhook.Object);

        await notifier.NotifyAsync(new NotificationMessage(
            NotificationKind.RenewalFailure, "subject", "body"));

        email.VerifyAll();
        webhook.VerifyAll();
        protector.VerifyAll();
    }

    [Fact]
    public async Task NotifyAsync_SuccessDisabled_DoesNotSend()
    {
        var configStore = MockConfig(new NotificationConfig
        {
            Smtp = new SmtpNotificationConfig(
                "smtp.example.com", 587, true, null, null, "from@example.com", "to@example.com"),
            NotifyOnSuccess = false
        });
        var email = new Mock<IEmailSender>(MockBehavior.Strict);
        var webhook = new Mock<IWebhookSender>(MockBehavior.Strict);
        var notifier = new Notifier(
            configStore.Object,
            Mock.Of<ISecretProtector>(),
            email.Object,
            webhook.Object);

        await notifier.NotifyAsync(new NotificationMessage(
            NotificationKind.RenewalSuccess, "subject", "body"));

        email.VerifyNoOtherCalls();
        webhook.VerifyNoOtherCalls();
    }

    private static Mock<IConfigStore> MockConfig(NotificationConfig notifications)
    {
        var configStore = new Mock<IConfigStore>(MockBehavior.Strict);
        configStore.Setup(value => value.LoadAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AppConfig { Notifications = notifications });
        return configStore;
    }
}
