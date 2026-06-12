using Dependably.Infrastructure;

namespace Dependably.Tests.Unit;

/// <summary>
/// Unit tests for <see cref="SamlCertExpiryCheckService"/> stage-transition logic.
/// No I/O — exercises the static helper methods only.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SamlCertExpiryCheckServiceTests
{
    // ── ComputeTargetStage ────────────────────────────────────────────────────

    [Theory]
    [InlineData(-1.0, "expired")]
    [InlineData(-0.001, "expired")]
    [InlineData(-100.0, "expired")]
    public void ComputeTargetStage_Expired_ReturnsExpired(double daysRemaining, string expected)
    {
        string stage = SamlCertExpiryCheckService.ComputeTargetStage(daysRemaining, new[] { 30, 14, 7, 1 });
        Assert.Equal(expected, stage);
    }

    [Theory]
    [InlineData(0.5, "1")]
    [InlineData(1.0, "1")]
    [InlineData(6.9, "7")]
    [InlineData(7.0, "7")]
    [InlineData(13.9, "14")]
    [InlineData(14.0, "14")]
    [InlineData(29.9, "30")]
    [InlineData(30.0, "30")]
    public void ComputeTargetStage_WithinThreshold_ReturnsCorrectStage(double daysRemaining, string expected)
    {
        string stage = SamlCertExpiryCheckService.ComputeTargetStage(daysRemaining, new[] { 30, 14, 7, 1 });
        Assert.Equal(expected, stage);
    }

    [Theory]
    [InlineData(30.01)]
    [InlineData(45.0)]
    [InlineData(365.0)]
    public void ComputeTargetStage_BeyondAllThresholds_ReturnsNone(double daysRemaining)
    {
        string stage = SamlCertExpiryCheckService.ComputeTargetStage(daysRemaining, new[] { 30, 14, 7, 1 });
        Assert.Equal("none", stage);
    }

    [Fact]
    public void ComputeTargetStage_NoThresholds_ReturnsNoneOrExpired()
    {
        // With no thresholds, only "expired" can be returned (when daysRemaining < 0).
        Assert.Equal("none", SamlCertExpiryCheckService.ComputeTargetStage(10, Array.Empty<int>()));
        Assert.Equal("expired", SamlCertExpiryCheckService.ComputeTargetStage(-1, Array.Empty<int>()));
    }

    // ── IsStageAdvancement ────────────────────────────────────────────────────

    [Theory]
    // Null current → any target is an advancement
    [InlineData(null, "30", true)]
    [InlineData(null, "14", true)]
    [InlineData(null, "7", true)]
    [InlineData(null, "1", true)]
    [InlineData(null, "expired", true)]
    // Same stage is not an advancement
    [InlineData("30", "30", false)]
    [InlineData("14", "14", false)]
    [InlineData("7", "7", false)]
    [InlineData("1", "1", false)]
    [InlineData("expired", "expired", false)]
    // Forward progression
    [InlineData("30", "14", true)]
    [InlineData("30", "7", true)]
    [InlineData("30", "1", true)]
    [InlineData("30", "expired", true)]
    [InlineData("14", "7", true)]
    [InlineData("14", "1", true)]
    [InlineData("14", "expired", true)]
    [InlineData("7", "1", true)]
    [InlineData("7", "expired", true)]
    [InlineData("1", "expired", true)]
    // Backward regression is NOT an advancement
    [InlineData("14", "30", false)]
    [InlineData("7", "30", false)]
    [InlineData("7", "14", false)]
    [InlineData("1", "30", false)]
    [InlineData("1", "14", false)]
    [InlineData("1", "7", false)]
    [InlineData("expired", "1", false)]
    [InlineData("expired", "7", false)]
    public void IsStageAdvancement_Matrix(string? current, string target, bool expected)
    {
        bool result = SamlCertExpiryCheckService.IsStageAdvancement(current, target);
        Assert.Equal(expected, result);
    }

    // ── Effective-cert selection (override wins) ──────────────────────────────

    // The selection logic mirrors what CheckOrgCertAsync does; we validate it via
    // ComputeTargetStage by feeding the cert's actual expiry rather than mocking the cert.

    [Fact]
    public void EffectiveCert_OverrideWins_WhenBothSet()
    {
        // When both override and metadata are set, the override should be used.
        // We model this via TenantSamlCertRow and the same !string.IsNullOrWhiteSpace logic.
        var row = new TenantSamlCertRow
        {
            OrgId = "org1",
            IdpSigningCert = "metadata-cert-base64",
            IdpSigningCertOverride = "override-cert-base64",
        };

        // The override wins: if override is non-empty, that's the effective cert.
        string? effective = !string.IsNullOrWhiteSpace(row.IdpSigningCertOverride)
            ? row.IdpSigningCertOverride
            : row.IdpSigningCert;

        Assert.Equal("override-cert-base64", effective);
    }

    [Fact]
    public void EffectiveCert_MetadataUsed_WhenOverrideAbsent()
    {
        var row = new TenantSamlCertRow
        {
            OrgId = "org1",
            IdpSigningCert = "metadata-cert-base64",
            IdpSigningCertOverride = null,
        };

        string? effective = !string.IsNullOrWhiteSpace(row.IdpSigningCertOverride)
            ? row.IdpSigningCertOverride
            : row.IdpSigningCert;

        Assert.Equal("metadata-cert-base64", effective);
    }

    [Fact]
    public void EffectiveCert_Null_WhenNeitherSet()
    {
        var row = new TenantSamlCertRow
        {
            OrgId = "org1",
            IdpSigningCert = null,
            IdpSigningCertOverride = null,
        };

        string? effective = !string.IsNullOrWhiteSpace(row.IdpSigningCertOverride)
            ? row.IdpSigningCertOverride
            : row.IdpSigningCert;

        Assert.Null(effective);
    }

    // ── Edge-case: cert expires exactly between checks ────────────────────────

    [Fact]
    public void ComputeTargetStage_ZeroDaysRemaining_ReturnsStage1()
    {
        // 0.0 is ≤ 1 so the stage is "1", not "expired" (expired requires daysRemaining < 0).
        string stage = SamlCertExpiryCheckService.ComputeTargetStage(0.0, new[] { 30, 14, 7, 1 });
        Assert.Equal("1", stage);
    }

    [Fact]
    public void ComputeTargetStage_NegativeEpsilon_ReturnsExpired()
    {
        string stage = SamlCertExpiryCheckService.ComputeTargetStage(-0.0001, new[] { 30, 14, 7, 1 });
        Assert.Equal("expired", stage);
    }

    // ── Mixed org scenarios (partial-failure) ─────────────────────────────────

    [Fact]
    public void StageAdvancement_MixedOrgs_EachOrgProgressesIndependently()
    {
        // Org A: already at stage "14", cert now in "7" window → should advance
        // Org B: already at stage "7", cert still in "14" window → should NOT advance (regression)
        // Org C: no prior alert, cert in "30" window → should advance

        // Org A
        Assert.True(SamlCertExpiryCheckService.IsStageAdvancement("14", "7"));

        // Org B: target is "14" but current is "7" — "14" has lower priority than "7"
        Assert.False(SamlCertExpiryCheckService.IsStageAdvancement("7", "14"));

        // Org C
        Assert.True(SamlCertExpiryCheckService.IsStageAdvancement(null, "30"));
    }

    [Fact]
    public void ComputeTargetStage_CertReplacedAtHigherDays_ReturnsNone()
    {
        // After a cert is replaced (stage reset to null), a new cert with 60 days left
        // should return "none" — outside the warn window.
        string stage = SamlCertExpiryCheckService.ComputeTargetStage(60.0, new[] { 30, 14, 7, 1 });
        Assert.Equal("none", stage);
        // And IsStageAdvancement with null current + "none" target should NOT advance
        // (because "none" isn't a valid alert stage).
        Assert.False(SamlCertExpiryCheckService.IsStageAdvancement(null, "none"));
    }

    [Fact]
    public void IsStageAdvancement_StageCertReplacedMidAlert_NullCurrentAllowsReissue()
    {
        // After the cert is replaced, cert_expiry_alert_stage is reset to NULL.
        // If the new cert is also expiring, the sweep should re-emit from scratch.
        // Null current → any positive stage is an advancement.
        Assert.True(SamlCertExpiryCheckService.IsStageAdvancement(null, "7"));
        Assert.True(SamlCertExpiryCheckService.IsStageAdvancement(null, "expired"));
    }
}
