using System.Xml.Linq;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Identity;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Identity;

/// <summary>
/// Unit tests for <see cref="DbXmlRepository"/>. Exercises store, round-trip, upsert, and
/// empty-table paths. Uses an in-memory SQLite database with the full schema applied so the
/// data_protection_keys table exists.
/// </summary>
[Trait("Category", "Unit")]
public sealed class DbXmlRepositoryTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
    }

    public async Task DisposeAsync()
    {
        await _db.DisposeAsync();
    }

    private DbXmlRepository Repository() =>
        new(_db, NullLogger<DbXmlRepository>.Instance);

    // ── empty table returns empty collection ──────────────────────────────────

    [Fact]
    public void GetAllElements_EmptyTable_ReturnsEmptyCollection()
    {
        var repo = Repository();
        var elements = repo.GetAllElements();
        Assert.Empty(elements);
    }

    // ── round-trip: store then retrieve ──────────────────────────────────────

    [Fact]
    public void StoreElement_ThenGetAllElements_RoundTripsXml()
    {
        var repo = Repository();
        var element = new XElement("key",
            new XAttribute("id", "key-1"),
            new XElement("creationDate", "2026-01-01"),
            new XElement("activationDate", "2026-01-01"));

        repo.StoreElement(element, "key-1");

        var retrieved = repo.GetAllElements();
        Assert.Single(retrieved);
        Assert.Equal(element.ToString(SaveOptions.DisableFormatting),
            retrieved.First().ToString(SaveOptions.DisableFormatting));
    }

    // ── upsert by friendly_name ───────────────────────────────────────────────

    [Fact]
    public void StoreElement_SameFriendlyName_OverwritesPreviousXml()
    {
        var repo = Repository();
        var original = new XElement("key", new XAttribute("version", "1"));
        var updated = new XElement("key", new XAttribute("version", "2"));

        repo.StoreElement(original, "my-key");
        repo.StoreElement(updated, "my-key");

        var retrieved = repo.GetAllElements();
        Assert.Single(retrieved);
        Assert.Equal(updated.ToString(SaveOptions.DisableFormatting),
            retrieved.First().ToString(SaveOptions.DisableFormatting));
    }

    // ── null/empty friendly name falls back to a generated guid ──────────────

    [Fact]
    public void StoreElement_NullFriendlyName_StoresWithGeneratedName()
    {
        var repo = Repository();
        var element = new XElement("key", new XAttribute("id", "auto"));

        repo.StoreElement(element, null!);

        var retrieved = repo.GetAllElements();
        Assert.Single(retrieved);
    }

    // ── multiple distinct keys all round-trip ─────────────────────────────────

    [Fact]
    public void StoreElement_MultipleKeys_AllRetrieved()
    {
        var repo = Repository();
        var a = new XElement("key", new XAttribute("id", "a"));
        var b = new XElement("key", new XAttribute("id", "b"));
        var c = new XElement("key", new XAttribute("id", "c"));

        repo.StoreElement(a, "key-a");
        repo.StoreElement(b, "key-b");
        repo.StoreElement(c, "key-c");

        var retrieved = repo.GetAllElements();
        Assert.Equal(3, retrieved.Count);
        Assert.Contains(retrieved, e => e.Attribute("id")?.Value == "a");
        Assert.Contains(retrieved, e => e.Attribute("id")?.Value == "b");
        Assert.Contains(retrieved, e => e.Attribute("id")?.Value == "c");
    }

    // ── mixed partial-failure: malformed row is skipped; valid rows returned ──

    [Fact]
    public async Task GetAllElements_MalformedRowInDb_SkipsAndReturnsValid()
    {
        // Seed a malformed xml row directly, bypassing the repository, to simulate
        // DB corruption or a future schema migration that produced invalid XML.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO data_protection_keys (friendly_name, xml) VALUES ('bad', 'NOT VALID XML <<<<')");
        }

        var repo = Repository();
        var good = new XElement("key", new XAttribute("id", "good"));
        repo.StoreElement(good, "good-key");

        var retrieved = repo.GetAllElements();

        // The valid row is returned; the malformed row is silently skipped.
        Assert.Single(retrieved);
        Assert.Equal("good", retrieved.First().Attribute("id")?.Value);
    }
}
