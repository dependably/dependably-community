using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class PackageNoteRepositoryTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('org1', 'org1'), ('org2', 'org2')");
        await conn.ExecuteAsync(
            "INSERT INTO users (id, tenant_id, email, password_hash, role) " +
            "VALUES ('user-1', 'org1', 'author@example.com', 'x', 'admin')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private PackageNoteRepository Repo() => new(_db, _clock);

    [Fact]
    public async Task Add_ThenList_RoundTripsAndResolvesAuthorLabel()
    {
        var repo = Repo();
        await repo.AddAsync("org1", "npm", "sharp", "0.33.0", "Bundled .so is not redistributed", "user-1");

        var note = Assert.Single(await repo.ListAsync("org1", "npm", "sharp", "0.33.0"));
        Assert.Equal("Bundled .so is not redistributed", note.Note);
        Assert.Equal("user-1", note.CreatedBy);
        Assert.Equal("author@example.com", note.CreatedByLabel);
        Assert.Equal(_clock.GetUtcNow(), note.CreatedAt);
    }

    // A package-wide note (NULL version) is about every version, so a version-scoped read must
    // surface it. Hiding it would make the version page the surface most likely to miss the note
    // that mattered.
    [Fact]
    public async Task List_ForOneVersion_IncludesPackageWideNotes()
    {
        var repo = Repo();
        await repo.AddAsync("org1", "npm", "sharp", null, "package-wide", "user-1");
        await repo.AddAsync("org1", "npm", "sharp", "0.33.0", "this version only", "user-1");

        var notes = await repo.ListAsync("org1", "npm", "sharp", "0.33.0");

        Assert.Equal(2, notes.Count);
        Assert.Contains(notes, n => n.Note == "package-wide");
        Assert.Contains(notes, n => n.Note == "this version only");
    }

    // Adversarial twin for the above: a note scoped to a *different* version must not leak into
    // this version's view.
    [Fact]
    public async Task List_ForOneVersion_ExcludesOtherVersionsNotes()
    {
        var repo = Repo();
        await repo.AddAsync("org1", "npm", "sharp", "0.32.0", "old version", "user-1");

        Assert.Empty(await repo.ListAsync("org1", "npm", "sharp", "0.33.0"));
    }

    [Fact]
    public async Task List_IsOrgScoped()
    {
        var repo = Repo();
        await repo.AddAsync("org1", "npm", "sharp", null, "org1 only", "user-1");

        Assert.Empty(await repo.ListAsync("org2", "npm", "sharp", null));
    }

    // The org_id predicate on update/delete is what stops a note id leaked from another tenant
    // being editable or removable here.
    [Fact]
    public async Task Update_FromAnotherOrg_DoesNothing()
    {
        var repo = Repo();
        var note = await repo.AddAsync("org1", "npm", "sharp", null, "original", "user-1");

        Assert.False(await repo.UpdateAsync("org2", note.Id, "tampered"));

        var stored = Assert.Single(await repo.ListAsync("org1", "npm", "sharp", null));
        Assert.Equal("original", stored.Note);
    }

    [Fact]
    public async Task Delete_FromAnotherOrg_DoesNothing()
    {
        var repo = Repo();
        var note = await repo.AddAsync("org1", "npm", "sharp", null, "keep me", "user-1");

        Assert.False(await repo.DeleteAsync("org2", note.Id));
        Assert.Single(await repo.ListAsync("org1", "npm", "sharp", null));
    }

    [Fact]
    public async Task Update_RewritesNoteAndStampsUpdatedAt()
    {
        var repo = Repo();
        var note = await repo.AddAsync("org1", "npm", "sharp", null, "before", "user-1");
        _clock.Advance(TimeSpan.FromHours(3));

        Assert.True(await repo.UpdateAsync("org1", note.Id, "after"));

        var stored = Assert.Single(await repo.ListAsync("org1", "npm", "sharp", null));
        Assert.Equal("after", stored.Note);
        Assert.Equal(_clock.GetUtcNow(), stored.UpdatedAt);
    }

    [Fact]
    public async Task Delete_RemovesTheRow()
    {
        var repo = Repo();
        var note = await repo.AddAsync("org1", "npm", "sharp", null, "gone soon", "user-1");

        Assert.True(await repo.DeleteAsync("org1", note.Id));
        Assert.Empty(await repo.ListAsync("org1", "npm", "sharp", null));
    }
}
