using Dependably.Infrastructure.Identity;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Dependably.Infrastructure.Startup;

/// <summary>
/// Wires the ASP.NET Core Identity spine for MFA: stores, hashers, and UserManager singletons
/// for both tenant users and system_admin accounts. No authentication scheme is added — the
/// existing JwtBearer and ApiToken schemes are unchanged.
/// </summary>
internal static class IdentityStartupExtensions
{
    internal static void AddDependablyIdentity(this WebApplicationBuilder builder)
    {
        // Stores and hashers are registered BEFORE AddIdentityCore so our implementations
        // win via the TryAdd semantics that AddIdentityCore uses internally. Registration
        // order is: master-key provider and envelope protector first, then MFA singletons
        // (protector, key provider, system token version store), then scoped stores, then
        // per-TUser hashers, then AddIdentityCore for each TUser type.

        builder.Services.TryAddSingleton<IMasterKeyProvider, EnvFileMasterKeyProvider>();
        builder.Services.AddSingleton<EnvelopeProtector>();

        builder.Services.AddSingleton<IMfaSecretProtector>(sp =>
        {
            var keyProvider = sp.GetRequiredService<MfaEncryptionKeyProvider>();
            // Block the thread briefly at startup to resolve the key synchronously.
            // MfaEncryptionKeyProvider.GetKeyAsync reads one DB row; the cost is negligible
            // at startup and avoids making the singleton factory async.
            byte[] key = keyProvider.GetKeyAsync().GetAwaiter().GetResult();
            return new MfaSecretProtector(key);
        });

        builder.Services.AddSingleton<IRecoveryCodeHasher>(sp =>
        {
            var keyProvider = sp.GetRequiredService<MfaEncryptionKeyProvider>();
            // Recovery-code hashing keys on the same per-instance MFA key as the authenticator
            // secret; resolving it here mirrors the IMfaSecretProtector registration above.
            byte[] key = keyProvider.GetKeyAsync().GetAwaiter().GetResult();
            // Legacy bare-SHA-256 recovery codes are rejected unless the operator opens a
            // migration window; a new install has no legacy rows and needs no opt-in.
            bool acceptLegacyCodes = builder.Configuration.GetValue("Mfa:AcceptLegacyRecoveryCodes", false);
            return new RecoveryCodeHasher(
                key,
                acceptLegacyCodes,
                sp.GetRequiredService<ILogger<RecoveryCodeHasher>>());
        });

        builder.Services.AddSingleton<MfaEncryptionKeyProvider>();
        builder.Services.AddSingleton<SystemAdminTokenVersionStore>();

        builder.Services.AddScoped<IUserStore<DependablyUser>, DependablyUserStore>();
        builder.Services.AddScoped<IUserStore<SystemAdminUser>, SystemAdminUserStore>();

        builder.Services.AddSingleton<IPasswordHasher<DependablyUser>, BcryptPasswordHasher<DependablyUser>>();
        builder.Services.AddSingleton<IPasswordHasher<SystemAdminUser>, BcryptPasswordHasher<SystemAdminUser>>();

        builder.Services
            .AddIdentityCore<DependablyUser>()
            .AddTokenProvider<AuthenticatorTokenProvider<DependablyUser>>(
                TokenOptions.DefaultAuthenticatorProvider);

        builder.Services
            .AddIdentityCore<SystemAdminUser>()
            .AddTokenProvider<AuthenticatorTokenProvider<SystemAdminUser>>(
                TokenOptions.DefaultAuthenticatorProvider);

        builder.Services.AddScoped<IMfaEnrollmentService, MfaEnrollmentService>();
        builder.Services.AddScoped<ISystemMfaEnrollmentService, SystemMfaEnrollmentService>();
    }
}
