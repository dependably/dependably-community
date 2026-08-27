using Dependably.Api;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Covers <see cref="PackageNoteController"/>'s four actions across their authorization,
/// validation and not-found branches.
///
/// <para>The split the tests are really about: reads need only <c>ReadPackages</c> so a developer
/// who hits a conditional licence can see why the org accepted it, while every write is an admin
/// decision. A member who could edit these notes could rewrite the recorded rationale for
/// accepting a package.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class PackageNoteControllerTests
{
    private static PackageNoteRequest Req(
        string ecosystem = "npm", string name = "left-pad", string? version = "1.3.0",
        string note = "Accepted under the conditional licence review of 2026-01.") =>
        new(ecosystem, name, version, note);

    private static async Task<ControllerScenarioResult> BuildAsync(string role)
    {
        var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: role);
        return await s.BuildAsync();
    }

    // ── Reads: member and above ──────────────────────────────────────────────

    [Fact]
    public async Task List_MemberCanRead()
    {
        await using var b = await BuildAsync("member");

        var result = await b.PackageNoteController.List("npm", "left-pad", null, CancellationToken.None);

        Assert.IsType<OkObjectResult>(result);
    }

    [Fact]
    public async Task List_AnonymousIsRefused()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        s.WithNoUser();
        await using var b = await s.BuildAsync();

        var result = await b.PackageNoteController.List("npm", "left-pad", null, CancellationToken.None);

        Assert.IsNotType<OkObjectResult>(result);
    }

    [Theory]
    [InlineData(null, "left-pad")]
    [InlineData("", "left-pad")]
    [InlineData("   ", "left-pad")]
    [InlineData("npm", null)]
    [InlineData("npm", "")]
    [InlineData("npm", "  ")]
    public async Task List_RequiresACoordinate(string? ecosystem, string? name)
    {
        await using var b = await BuildAsync("admin");

        var result = await b.PackageNoteController.List(ecosystem, name, null, CancellationToken.None);

        Assert.IsNotType<OkObjectResult>(result);
    }

    // ── Writes: admin and above ──────────────────────────────────────────────

    [Fact]
    public async Task Add_MemberIsRefused()
    {
        // The load-bearing half of the split: a member reading the rationale is fine, a member
        // rewriting it is not.
        await using var b = await BuildAsync("member");

        var result = await b.PackageNoteController.Add(Req(), CancellationToken.None);

        Assert.IsNotType<CreatedAtActionResult>(result);
    }

    [Fact]
    public async Task Add_AdminCreatesTheNote()
    {
        await using var b = await BuildAsync("admin");

        var result = await b.PackageNoteController.Add(Req(), CancellationToken.None);

        Assert.IsType<CreatedAtActionResult>(result);

        var listed = Assert.IsType<OkObjectResult>(
            await b.PackageNoteController.List("npm", "left-pad", null, CancellationToken.None));
        Assert.NotNull(listed.Value);
    }

    [Fact]
    public async Task Add_TrimsTheCoordinateAndNote()
    {
        await using var b = await BuildAsync("admin");

        var created = Assert.IsType<CreatedAtActionResult>(await b.PackageNoteController.Add(
            Req(ecosystem: "  npm  ", name: "  left-pad  ", version: "  1.3.0  ", note: "  spaced  "),
            CancellationToken.None));

        // Listing by the trimmed coordinate finds it, which is the whole point of trimming on write.
        var listed = Assert.IsType<OkObjectResult>(
            await b.PackageNoteController.List("npm", "left-pad", "1.3.0", CancellationToken.None));
        Assert.NotNull(created.Value);
        Assert.NotNull(listed.Value);
    }

    [Fact]
    public async Task Add_BlankVersionMeansPackageWide()
    {
        await using var b = await BuildAsync("admin");

        Assert.IsType<CreatedAtActionResult>(await b.PackageNoteController.Add(
            Req(version: "   "), CancellationToken.None));
    }

    [Theory]
    [InlineData("", "left-pad")]
    [InlineData("npm", "")]
    public async Task Add_RequiresACoordinate(string ecosystem, string name)
    {
        await using var b = await BuildAsync("admin");

        var result = await b.PackageNoteController.Add(
            Req(ecosystem: ecosystem, name: name), CancellationToken.None);

        Assert.IsNotType<CreatedAtActionResult>(result);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task Add_RequiresANote(string note)
    {
        await using var b = await BuildAsync("admin");

        var result = await b.PackageNoteController.Add(Req(note: note), CancellationToken.None);

        Assert.IsNotType<CreatedAtActionResult>(result);
    }

    [Fact]
    public async Task Add_BoundsTheNoteLength()
    {
        // A compliance note is a paragraph, not a document — one tenant must not park megabytes
        // of prose on a row every package view reads.
        await using var b = await BuildAsync("admin");

        Assert.IsType<CreatedAtActionResult>(await b.PackageNoteController.Add(
            Req(note: new string('n', PackageNoteController.MaxNoteLength)),
            CancellationToken.None));

        Assert.IsNotType<CreatedAtActionResult>(await b.PackageNoteController.Add(
            Req(note: new string('n', PackageNoteController.MaxNoteLength + 1)),
            CancellationToken.None));
    }

    // ── Update ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task Update_MemberIsRefused()
    {
        await using var b = await BuildAsync("member");

        var result = await b.PackageNoteController.Update(
            "any-id", new PackageNoteUpdateRequest("rewritten"), CancellationToken.None);

        Assert.IsNotType<NoContentResult>(result);
    }

    [Fact]
    public async Task Update_UnknownIdIsNotFound()
    {
        await using var b = await BuildAsync("admin");

        var result = await b.PackageNoteController.Update(
            "no-such-note", new PackageNoteUpdateRequest("rewritten"), CancellationToken.None);

        Assert.IsType<NotFoundResult>(result);
    }

    [Theory]
    [InlineData("")]
    [InlineData("  ")]
    public async Task Update_RequiresANote(string note)
    {
        await using var b = await BuildAsync("admin");

        var result = await b.PackageNoteController.Update(
            "any-id", new PackageNoteUpdateRequest(note), CancellationToken.None);

        Assert.IsNotType<NoContentResult>(result);
        Assert.IsNotType<NotFoundResult>(result);   // refused on validation, before the lookup
    }

    [Fact]
    public async Task Update_BoundsTheNoteLength()
    {
        await using var b = await BuildAsync("admin");

        var result = await b.PackageNoteController.Update(
            "any-id",
            new PackageNoteUpdateRequest(new string('n', PackageNoteController.MaxNoteLength + 1)),
            CancellationToken.None);

        Assert.IsNotType<NoContentResult>(result);
        Assert.IsNotType<NotFoundResult>(result);
    }

    // ── Delete ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task Delete_MemberIsRefused()
    {
        await using var b = await BuildAsync("member");

        var result = await b.PackageNoteController.Delete("any-id", CancellationToken.None);

        Assert.IsNotType<NoContentResult>(result);
    }

    [Fact]
    public async Task Delete_UnknownIdIsNotFound()
    {
        await using var b = await BuildAsync("admin");

        var result = await b.PackageNoteController.Delete("no-such-note", CancellationToken.None);

        Assert.IsType<NotFoundResult>(result);
    }
}
