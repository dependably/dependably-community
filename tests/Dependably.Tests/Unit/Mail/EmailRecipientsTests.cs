using Dependably.Infrastructure.Mail;

namespace Dependably.Tests.Unit.Mail;

/// <summary>
/// <see cref="EmailRecipients"/>: the comma-separated recipient parser/validator shared by the
/// org email-settings PUT and the delivery-config read path.
/// </summary>
[Trait("Category", "Unit")]
public sealed class EmailRecipientsTests
{
    [Fact]
    public void Validate_ValidList_ReturnsTrimmedAddresses()
    {
        var (recipients, resourceKey) = EmailRecipients.Validate(" a@example.com , b@example.com,c@example.com ");

        Assert.Null(resourceKey);
        Assert.NotNull(recipients);
        Assert.Equal(["a@example.com", "b@example.com", "c@example.com"], recipients!);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Validate_EmptyOrBlank_ReturnsEmptyArray(string? raw)
    {
        var (recipients, resourceKey) = EmailRecipients.Validate(raw);

        Assert.Null(resourceKey);
        Assert.NotNull(recipients);
        Assert.Empty(recipients!);
    }

    [Fact]
    public void Validate_OneInvalidEntry_RejectsWholeList()
    {
        var (recipients, resourceKey) = EmailRecipients.Validate("valid@example.com,not-an-email");

        Assert.Null(recipients);
        Assert.Equal("error.email.invalidRecipient", resourceKey);
    }

    /// <summary>
    /// A CR/LF embedded in an entry (an attempt to smuggle an extra SMTP/MIME header via the
    /// recipient field) fails <see cref="System.Net.Mail.MailAddress.TryCreate(string, out System.Net.Mail.MailAddress?)"/>
    /// parsing rather than silently splitting into a second address.
    /// </summary>
    [Theory]
    [InlineData("victim@example.com\r\nBcc: attacker@evil.com")]
    [InlineData("victim@example.com\nX-Injected: true")]
    public void Validate_HeaderInjectionAttempt_Rejected(string malicious)
    {
        var (recipients, resourceKey) = EmailRecipients.Validate(malicious);

        Assert.Null(recipients);
        Assert.Equal("error.email.invalidRecipient", resourceKey);
    }

    [Fact]
    public void Validate_MoreThanMax_RejectsWithCapError()
    {
        string raw = string.Join(",", Enumerable.Range(0, EmailRecipients.MaxRecipients + 1)
            .Select(i => $"user{i}@example.com"));

        var (recipients, resourceKey) = EmailRecipients.Validate(raw);

        Assert.Null(recipients);
        Assert.Equal("error.email.tooManyRecipients", resourceKey);
    }

    [Fact]
    public void Validate_ExactlyMax_Accepted()
    {
        string raw = string.Join(",", Enumerable.Range(0, EmailRecipients.MaxRecipients)
            .Select(i => $"user{i}@example.com"));

        var (recipients, resourceKey) = EmailRecipients.Validate(raw);

        Assert.Null(resourceKey);
        Assert.Equal(EmailRecipients.MaxRecipients, recipients!.Length);
    }

    [Fact]
    public void Split_EmptyEntriesAndWhitespace_Removed()
    {
        string[] result = EmailRecipients.Split("a@example.com,, ,b@example.com,");
        Assert.Equal(["a@example.com", "b@example.com"], result);
    }
}
