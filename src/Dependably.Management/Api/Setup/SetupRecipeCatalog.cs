using static Dependably.Api.Setup.SetupVocabulary;

namespace Dependably.Api.Setup;

/// <summary>
/// Builds the client-configuration recipes served by <c>GET /api/v1/setup/{ecosystem}</c>.
///
/// Lives outside the controller so the whole matrix is reachable from a plain unit test:
/// the recipes are the product surface here, and a gate that can only see them through an
/// HTTP host would be testing the routing rather than the content.
///
/// Two rules hold across every builder below.
///
/// **A project-scoped file never holds the literal token.** Project files are committed,
/// so they reference an environment variable in whatever syntax the tool actually
/// interpolates — and that syntax differs per tool (<c>${VAR}</c> for npm and pip,
/// <c>%VAR%</c> for NuGet, <c>${env.VAR}</c> for Maven). Where a project recipe still
/// needs a credential, it carries a second file marked <see cref="SetupFile.SecretBearing"/>
/// that lives in the developer's home directory. Global-scoped files are not under source
/// control, so they hold the literal value and the page tells the reader to tighten
/// permissions.
///
/// **A cell that does not exist is not emitted.** Go, apk and Terraform are proxy-only and
/// so have no publish recipes; Docker has no project scope. The page renders the absence,
/// rather than a recipe that would not work.
///
/// Registry path prefixes are fixed by each ecosystem's own specification and are mirrored
/// in <c>web/src/lib/installCommand.js</c>'s BASE_PATHS — a change here needs a matching
/// change there.
/// </summary>
public static class SetupRecipeCatalog
{
    /// <summary>
    /// The recipes for one ecosystem, or null when the ecosystem is unknown.
    /// </summary>
    /// <param name="ecosystem">Ecosystem key, matching <c>web/src/lib/ecosystems.js</c>.</param>
    /// <param name="baseUrl">Tenant-implicit base URL, with no trailing slash.</param>
    public static SetupRecipesResponse? Build(string ecosystem, string baseUrl) => ecosystem switch
    {
        "npm" => Npm(baseUrl),
        "pypi" => PyPi(baseUrl),
        "nuget" => NuGet(baseUrl),
        "maven" => Maven(baseUrl),
        "cargo" => Cargo(baseUrl),
        "oci" => Oci(baseUrl),
        "golang" => Go(baseUrl),
        "rpm" => Rpm(baseUrl),
        "apk" => Apk(baseUrl),
        "terraform" => Terraform(baseUrl),
        _ => null
    };

    // ── Shared helpers ────────────────────────────────────────────────────────

    private static string HostOf(string baseUrl) => new Uri(baseUrl).Host;

    private static string AuthorityOf(string baseUrl) => new Uri(baseUrl).Authority;

    /// <summary>
    /// True when this deployment is served over plain HTTP. Most package managers refuse a
    /// plaintext registry by default, so each ecosystem's HTTP override is attached as a
    /// caveat only when it is actually needed — an HTTPS deployment should not be told to
    /// weaken anything.
    /// </summary>
    private static bool IsPlainHttp(string baseUrl) =>
        string.Equals(new Uri(baseUrl).Scheme, "http", StringComparison.Ordinal);

    private static IReadOnlyList<string> Caveats(params string?[] ids) =>
        ids.Where(id => id is not null).Select(id => id!).ToArray();

    private static SetupFile File(string path, string? locationHint, string language, string body, bool secretBearing = false) =>
        new(path, locationHint, language, body, secretBearing);

    // Location hints are identifiers the client resolves to copy, not prose.
    private const string InRepoRoot = "repoRoot";
    private const string InHomeDir = "homeDir";
    private const string InWorkspaceRoot = "workspaceRoot";
    private const string OnEachMachine = "eachMachine";

    // Caveat identifiers. Only the gotchas that demand an action *outside* this page earn
    // one: a plain-HTTP override the recipe already writes into the file explains itself in
    // the file, where it travels with the paste. `insecureRegistry` and `httpMirror` are
    // shared with installCommand.js's CAVEATS so the two surfaces word them identically.
    private const string CaveatMavenBlocked = "httpMavenBlocked";
    private const string CaveatCleartextCredentials = "httpCleartextCredentials";
    private const string CaveatInsecureRegistry = "insecureRegistry";
    private const string CaveatHttpMirror = "httpMirror";

    // ── npm ───────────────────────────────────────────────────────────────────

    private static SetupRecipesResponse Npm(string baseUrl)
    {
        string registryUrl = $"{baseUrl}/npm/";
        // npm keys the auth token by the registry URL with the scheme stripped.
        string authKey = registryUrl[(registryUrl.IndexOf("://", StringComparison.Ordinal) + 3)..];
        // The plain-HTTP override is explained in the file rather than in a page callout:
        // the comment travels with the paste, so the next person to open .npmrc and wonder
        // why TLS checking is off has the answer in front of them.
        string strictSslLine = IsPlainHttp(baseUrl)
            ? "\n\n# This registry is served over plain HTTP; npm refuses that without:\nstrict-ssl=false"
            : "";

        string ProjectBody() => $"registry={registryUrl}\n//{authKey}:_authToken=${{NPM_TOKEN}}{strictSslLine}";
        string GlobalBody(string token) => $"registry={registryUrl}\n//{authKey}:_authToken={token}{strictSslLine}";

        var recipes = new List<SetupRecipe>
        {
            new(Variant: "npm", OperationInstall, ScopeProject, PresetPull,
                Files: [File(".npmrc", InRepoRoot, "ini", ProjectBody())],
                TokenDelivery: SetupTokenDelivery.FromEnvVar("NPM_TOKEN"),
                Verify: "npm ping\nnpm whoami\nnpm view is-odd registry",
                Caveats: []),

            new(Variant: "npm", OperationInstall, ScopeGlobal, PresetPull,
                Files: [File("~/.npmrc", InHomeDir, "ini", GlobalBody("<token>"), secretBearing: true)],
                TokenDelivery: SetupTokenDelivery.Literal(),
                Verify: "npm config get registry\nnpm ping\nnpm whoami\nnpm install is-odd",
                Caveats: []),

            new(Variant: "npm", OperationPublish, ScopeProject, PresetPush,
                Files: [File(".npmrc", InRepoRoot, "ini", ProjectBody())],
                TokenDelivery: SetupTokenDelivery.FromEnvVar("NPM_TOKEN"),
                Verify: "npm whoami\nnpm publish --dry-run\nnpm publish",
                Caveats: []),

            new(Variant: "npm", OperationPublish, ScopeGlobal, PresetPush,
                Files: [File("~/.npmrc", InHomeDir, "ini", GlobalBody("<token>"), secretBearing: true)],
                TokenDelivery: SetupTokenDelivery.Literal(),
                Verify: "npm whoami\nnpm publish --dry-run\nnpm publish",
                Caveats: []),
        };

        return new SetupRecipesResponse("npm", [new SetupVariant("npm", "npm")], recipes);
    }

    // ── PyPI ──────────────────────────────────────────────────────────────────

    private static SetupRecipesResponse PyPi(string baseUrl)
    {
        string host = HostOf(baseUrl);
        string authority = AuthorityOf(baseUrl);
        string scheme = new Uri(baseUrl).Scheme;
        string indexUrl = $"{baseUrl}/simple/";
        string trustedHostLine = IsPlainHttp(baseUrl)
            ? $"\n# This registry is served over plain HTTP; pip refuses that without:\ntrusted-host = {host}"
            : "";

        var recipes = new List<SetupRecipe>
        {
            // pip interpolates ${VAR} in its config files, so the project file carries the
            // credential by reference and stays committable.
            new(Variant: "pip", OperationInstall, ScopeProject, PresetPull,
                Files:
                [
                    File("pip.conf", InRepoRoot, "ini",
                        $"[global]\nindex-url = {scheme}://user:${{DEPENDABLY_TOKEN}}@{authority}/simple/{trustedHostLine}")
                ],
                TokenDelivery: SetupTokenDelivery.FromEnvVar("DEPENDABLY_TOKEN"),
                // pip reads the user-level file unless pointed at this one explicitly.
                Verify: "PIP_CONFIG_FILE=./pip.conf pip config list\nPIP_CONFIG_FILE=./pip.conf pip install requests",
                Caveats: []),

            new(Variant: "pip", OperationInstall, ScopeGlobal, PresetPull,
                Files:
                [
                    File("~/.config/pip/pip.conf", InHomeDir, "ini",
                        $"[global]\nindex-url = {scheme}://user:<token>@{authority}/simple/{trustedHostLine}",
                        secretBearing: true)
                ],
                TokenDelivery: SetupTokenDelivery.Literal(),
                Verify: "pip config list\npip install requests",
                Caveats: []),

            // Poetry and uv keep their own configuration, independent of pip's. Both store
            // the credential outside the project file, so neither project file is secret-bearing.
            new(Variant: "poetry", OperationInstall, ScopeProject, PresetPull,
                Files:
                [
                    File("pyproject.toml", InRepoRoot, "toml",
                        $"[[tool.poetry.source]]\nname = \"dependably\"\nurl = \"{indexUrl}\"\npriority = \"primary\"")
                ],
                TokenDelivery: SetupTokenDelivery.FromCommand("poetry config http-basic.dependably user <token>"),
                Verify: "poetry check\npoetry add requests",
                Caveats: []),

            new(Variant: "uv", OperationInstall, ScopeProject, PresetPull,
                Files:
                [
                    File("pyproject.toml", InRepoRoot, "toml",
                        $"[[tool.uv.index]]\nname = \"dependably\"\nurl = \"{indexUrl}\"\ndefault = true")
                ],
                // uv reads credentials from the environment by index name, as a pair that
                // appears in no file — so this is an export, not a file interpolation.
                TokenDelivery: SetupTokenDelivery.FromCommand(
                    "export UV_INDEX_DEPENDABLY_USERNAME=user\nexport UV_INDEX_DEPENDABLY_PASSWORD=<token>"),
                Verify: "uv add requests",
                Caveats: []),

            // twine reads ~/.pypirc only; there is no project-scoped publish configuration.
            new(Variant: "twine", OperationPublish, ScopeGlobal, PresetPush,
                Files:
                [
                    File("~/.pypirc", InHomeDir, "ini",
                        $"[distutils]\nindex-servers = dependably\n\n[dependably]\nrepository = {baseUrl}/simple/\nusername = user\npassword = <token>",
                        secretBearing: true)
                ],
                TokenDelivery: SetupTokenDelivery.Literal(),
                Verify: "python -m build\ntwine check dist/*\ntwine upload --repository dependably dist/*",
                Caveats: []),
        };

        var variants = new[]
        {
            new SetupVariant("pip", "pip"),
            new SetupVariant("poetry", "Poetry"),
            new SetupVariant("uv", "uv"),
            new SetupVariant("twine", "twine"),
        };

        return new SetupRecipesResponse("pypi", variants, recipes);
    }

    // ── NuGet ─────────────────────────────────────────────────────────────────

    private static SetupRecipesResponse NuGet(string baseUrl)
    {
        string indexUrl = $"{baseUrl}/nuget/v3/index.json";
        bool http = IsPlainHttp(baseUrl);
        // Modern dotnet refuses an HTTP feed unless the source opts in explicitly. Said in
        // the file rather than in a page callout, so the opt-in carries its reason with it.
        string insecureAttr = http
            ? "\n             allowInsecureConnections=\"true\" <!-- served over plain HTTP -->"
            : "";
        string insecureFlag = http ? " --allow-insecure-connections" : "";

        // NuGet interpolates %VAR% inside ClearTextPassword at restore time, which is what
        // lets the committed project config carry the credential by reference.
        string projectConfig = $"""
            <?xml version="1.0" encoding="utf-8"?>
            <configuration>
              <packageSources>
                <clear />
                <add key="dependably"
                     value="{indexUrl}"{insecureAttr} />
              </packageSources>
              <packageSourceCredentials>
                <dependably>
                  <add key="Username" value="user" />
                  <add key="ClearTextPassword" value="%DEPENDABLY_TOKEN%" />
                </dependably>
              </packageSourceCredentials>
            </configuration>
            """;

        var recipes = new List<SetupRecipe>
        {
            new(Variant: "dotnet", OperationInstall, ScopeProject, PresetPull,
                Files: [File("NuGet.config", InRepoRoot, "xml", projectConfig)],
                TokenDelivery: SetupTokenDelivery.FromEnvVar("DEPENDABLY_TOKEN"),
                Verify: "dotnet nuget list source\ndotnet restore\ndotnet add package Newtonsoft.Json",
                Caveats: []),

            // The user-level config path differs per OS, so the CLI is the recipe here
            // rather than a file whose location the page would have to guess.
            new(Variant: "dotnet", OperationInstall, ScopeGlobal, PresetPull,
                Files: [],
                TokenDelivery: SetupTokenDelivery.FromCommand(
                    $"dotnet nuget add source {indexUrl} \\\n  --name dependably \\\n  --username user \\\n  --password <token> \\\n  --store-password-in-clear-text{insecureFlag}"),
                Verify: "dotnet nuget list source\ndotnet add package Newtonsoft.Json",
                Caveats: []),

            // Push authenticates with an API key, not the packageSourceCredentials above.
            new(Variant: "dotnet", OperationPublish, ScopeProject, PresetPush,
                Files: [File("NuGet.config", InRepoRoot, "xml", projectConfig)],
                TokenDelivery: SetupTokenDelivery.FromEnvVar("DEPENDABLY_TOKEN"),
                Verify: "dotnet pack -c Release\ndotnet nuget push bin/Release/*.nupkg --api-key $DEPENDABLY_TOKEN --source dependably",
                Caveats: []),

            new(Variant: "dotnet", OperationPublish, ScopeGlobal, PresetPush,
                Files: [],
                TokenDelivery: SetupTokenDelivery.FromCommand(
                    $"dotnet nuget add source {indexUrl} \\\n  --name dependably \\\n  --username user \\\n  --password <token> \\\n  --store-password-in-clear-text{insecureFlag}"),
                Verify: "dotnet pack -c Release\ndotnet nuget push bin/Release/*.nupkg --api-key <token> --source dependably",
                Caveats: []),
        };

        return new SetupRecipesResponse("nuget", [new SetupVariant("dotnet", ".NET CLI")], recipes);
    }

    // ── Maven / Gradle ────────────────────────────────────────────────────────

    private static SetupRecipesResponse Maven(string baseUrl)
    {
        string repoUrl = $"{baseUrl}/maven/";
        // Maven 3.8.1+ blocks plaintext HTTP repositories outright, so the override is a
        // mirror declaration rather than a per-tool flag.
        string? httpCaveat = IsPlainHttp(baseUrl) ? CaveatMavenBlocked : null;

        // The <server> id must match the <repository> id — that is how Maven attaches
        // credentials to a repository.
        string SettingsXml(string password, string? repositories) => $"""
            <settings>
              <servers>
                <server>
                  <id>dependably</id>
                  <username>user</username>
                  <password>{password}</password>
                </server>
              </servers>{repositories}
            </settings>
            """;

        string profileBlock = $"""

              <profiles>
                <profile>
                  <id>dependably</id>
                  <repositories>
                    <repository>
                      <id>dependably</id>
                      <url>{repoUrl}</url>
                    </repository>
                  </repositories>
                </profile>
              </profiles>
              <activeProfiles><activeProfile>dependably</activeProfile></activeProfiles>
            """;

        string pomRepositories = $"""
            <repositories>
              <repository>
                <id>dependably</id>
                <url>{repoUrl}</url>
              </repository>
            </repositories>
            """;

        string pomDistribution = $"""
            <distributionManagement>
              <repository>
                <id>dependably</id>
                <url>{repoUrl}</url>
              </repository>
            </distributionManagement>
            """;

        // Gradle resolves the credential from a project property first and falls back to the
        // environment, so one build script serves both a developer's gradle.properties and CI.
        string GradleGroovy(bool publishing) => $$"""
            repositories {
                maven {
                    url '{{repoUrl}}'
                    credentials {
                        username = 'user'
                        password = findProperty('dependablyToken') ?: System.getenv('DEPENDABLY_TOKEN')
                    }
                }
            }
            """ + (publishing ? $$"""

            publishing {
                repositories {
                    maven {
                        url '{{repoUrl}}'
                        credentials {
                            username = 'user'
                            password = findProperty('dependablyToken') ?: System.getenv('DEPENDABLY_TOKEN')
                        }
                    }
                }
            }
            """ : "");

        string GradleKotlin(bool publishing) => $$"""
            repositories {
                maven {
                    url = uri("{{repoUrl}}")
                    credentials {
                        username = "user"
                        password = (findProperty("dependablyToken") as String?) ?: System.getenv("DEPENDABLY_TOKEN")
                    }
                }
            }
            """ + (publishing ? $$"""

            publishing {
                repositories {
                    maven {
                        url = uri("{{repoUrl}}")
                        credentials {
                            username = "user"
                            password = (findProperty("dependablyToken") as String?) ?: System.getenv("DEPENDABLY_TOKEN")
                        }
                    }
                }
            }
            """ : "");

        var recipes = new List<SetupRecipe>
        {
            // Maven interpolates ${env.VAR} in settings.xml, so the project-scoped recipe
            // keeps the literal token out of both files.
            new(Variant: "maven", OperationInstall, ScopeProject, PresetPull,
                Files:
                [
                    File("pom.xml", InRepoRoot, "xml", pomRepositories),
                    File("~/.m2/settings.xml", OnEachMachine, "xml", SettingsXml("${env.DEPENDABLY_TOKEN}", null)),
                ],
                TokenDelivery: SetupTokenDelivery.FromEnvVar("DEPENDABLY_TOKEN"),
                Verify: "mvn -q dependency:get -Dartifact=org.slf4j:slf4j-api:2.0.13\nmvn dependency:resolve",
                Caveats: Caveats(httpCaveat)),

            new(Variant: "maven", OperationInstall, ScopeGlobal, PresetPull,
                Files: [File("~/.m2/settings.xml", InHomeDir, "xml", SettingsXml("<token>", profileBlock), secretBearing: true)],
                TokenDelivery: SetupTokenDelivery.Literal(),
                Verify: "mvn -q dependency:get -Dartifact=org.slf4j:slf4j-api:2.0.13",
                Caveats: Caveats(httpCaveat)),

            new(Variant: "maven", OperationPublish, ScopeProject, PresetPush,
                Files:
                [
                    File("pom.xml", InRepoRoot, "xml", pomDistribution),
                    File("~/.m2/settings.xml", OnEachMachine, "xml", SettingsXml("${env.DEPENDABLY_TOKEN}", null)),
                ],
                TokenDelivery: SetupTokenDelivery.FromEnvVar("DEPENDABLY_TOKEN"),
                Verify: "mvn deploy -DskipTests",
                Caveats: Caveats(httpCaveat)),

            new(Variant: "gradle-groovy", OperationInstall, ScopeProject, PresetPull,
                Files: [File("build.gradle", InRepoRoot, "groovy", GradleGroovy(publishing: false))],
                TokenDelivery: SetupTokenDelivery.FromEnvVar("DEPENDABLY_TOKEN"),
                Verify: "./gradlew dependencies --refresh-dependencies",
                Caveats: Caveats(httpCaveat)),

            new(Variant: "gradle-groovy", OperationPublish, ScopeProject, PresetPush,
                Files: [File("build.gradle", InRepoRoot, "groovy", GradleGroovy(publishing: true))],
                TokenDelivery: SetupTokenDelivery.FromEnvVar("DEPENDABLY_TOKEN"),
                Verify: "./gradlew publish",
                Caveats: Caveats(httpCaveat)),

            new(Variant: "gradle-groovy", OperationInstall, ScopeGlobal, PresetPull,
                Files: [File("~/.gradle/gradle.properties", InHomeDir, "ini", "dependablyToken=<token>", secretBearing: true)],
                TokenDelivery: SetupTokenDelivery.Literal(),
                Verify: "./gradlew dependencies --refresh-dependencies",
                Caveats: Caveats(httpCaveat)),

            new(Variant: "gradle-kotlin", OperationInstall, ScopeProject, PresetPull,
                Files: [File("build.gradle.kts", InRepoRoot, "kotlin", GradleKotlin(publishing: false))],
                TokenDelivery: SetupTokenDelivery.FromEnvVar("DEPENDABLY_TOKEN"),
                Verify: "./gradlew dependencies --refresh-dependencies",
                Caveats: Caveats(httpCaveat)),

            new(Variant: "gradle-kotlin", OperationPublish, ScopeProject, PresetPush,
                Files: [File("build.gradle.kts", InRepoRoot, "kotlin", GradleKotlin(publishing: true))],
                TokenDelivery: SetupTokenDelivery.FromEnvVar("DEPENDABLY_TOKEN"),
                Verify: "./gradlew publish",
                Caveats: Caveats(httpCaveat)),

            new(Variant: "gradle-kotlin", OperationInstall, ScopeGlobal, PresetPull,
                Files: [File("~/.gradle/gradle.properties", InHomeDir, "ini", "dependablyToken=<token>", secretBearing: true)],
                TokenDelivery: SetupTokenDelivery.Literal(),
                Verify: "./gradlew dependencies --refresh-dependencies",
                Caveats: Caveats(httpCaveat)),
        };

        var variants = new[]
        {
            // Labelled by the build file rather than the DSL: a reader who does not know
            // whether their Gradle build is Groovy or Kotlin can always see which file exists.
            new SetupVariant("maven", "Maven (pom.xml)"),
            new SetupVariant("gradle-groovy", "Gradle (build.gradle)"),
            new SetupVariant("gradle-kotlin", "Gradle (build.gradle.kts)"),
        };

        return new SetupRecipesResponse("maven", variants, recipes);
    }

    // ── Cargo ─────────────────────────────────────────────────────────────────

    private static SetupRecipesResponse Cargo(string baseUrl)
    {
        string indexUrl = $"sparse+{baseUrl}/cargo/";
        string protocolLine = IsPlainHttp(baseUrl)
            ? "\n# This registry is served over plain HTTP; Cargo needs the protocol stated:\nprotocol = \"sparse\""
            : "";

        // The source-replacement block routes every crate through Dependably; without it the
        // registry only serves crates that name it explicitly.
        string configToml = $"""
            [registries.dependably]
            index = "{indexUrl}"{protocolLine}

            [source.crates-io]
            replace-with = "dependably"

            [source.dependably]
            registry = "{indexUrl}"
            """;

        var recipes = new List<SetupRecipe>
        {
            // The workspace config names the registry but never the credential — that lives in
            // the developer's own credentials file, written by `cargo login`.
            new(Variant: "cargo", OperationInstall, ScopeProject, PresetPull,
                Files: [File(".cargo/config.toml", InWorkspaceRoot, "toml", configToml)],
                TokenDelivery: SetupTokenDelivery.FromCommand("cargo login --registry dependably"),
                Verify: "cargo build\ncargo tree",
                Caveats: []),

            new(Variant: "cargo", OperationInstall, ScopeGlobal, PresetPull,
                Files:
                [
                    File("~/.cargo/config.toml", InHomeDir, "toml", configToml),
                    File("~/.cargo/credentials.toml", InHomeDir, "toml",
                        "[registries.dependably]\ntoken = \"<token>\"", secretBearing: true),
                ],
                TokenDelivery: SetupTokenDelivery.Literal(),
                Verify: "cargo build",
                Caveats: []),

            new(Variant: "cargo", OperationPublish, ScopeProject, PresetPush,
                Files: [File(".cargo/config.toml", InWorkspaceRoot, "toml", configToml)],
                // Cargo reads this variable by registry name; it is named in no file, which is
                // what keeps the committed workspace config free of the credential.
                TokenDelivery: SetupTokenDelivery.FromCommand(
                    "export CARGO_REGISTRIES_DEPENDABLY_TOKEN=<token>"),
                Verify: "cargo publish --registry dependably --dry-run\ncargo publish --registry dependably",
                Caveats: []),

            new(Variant: "cargo", OperationPublish, ScopeGlobal, PresetPush,
                Files:
                [
                    File("~/.cargo/config.toml", InHomeDir, "toml", configToml),
                    File("~/.cargo/credentials.toml", InHomeDir, "toml",
                        "[registries.dependably]\ntoken = \"<token>\"", secretBearing: true),
                ],
                TokenDelivery: SetupTokenDelivery.Literal(),
                Verify: "cargo publish --registry dependably --dry-run\ncargo publish --registry dependably",
                Caveats: []),
        };

        return new SetupRecipesResponse("cargo", [new SetupVariant("cargo", "Cargo")], recipes);
    }

    // ── Docker / OCI ──────────────────────────────────────────────────────────

    private static SetupRecipesResponse Oci(string baseUrl)
    {
        string host = HostOf(baseUrl);
        // A plain-HTTP registry needs a daemon-level opt-in; there is no per-command flag.
        string? httpCaveat = IsPlainHttp(baseUrl) ? CaveatInsecureRegistry : null;
        var daemonFile = IsPlainHttp(baseUrl)
            ? new[]
            {
                File("/etc/docker/daemon.json", null, "json",
                    $"{{ \"insecure-registries\": [\"{host}\"] }}")
            }
            : [];

        // The Distribution Spec puts the registry host in the image reference itself, so there
        // is no project-scoped configuration file to write — only a host-level login.
        var recipes = new List<SetupRecipe>
        {
            new(Variant: "docker", OperationInstall, ScopeGlobal, PresetPull,
                Files: daemonFile,
                TokenDelivery: SetupTokenDelivery.FromCommand($"echo <token> | docker login {host} --username user --password-stdin"),
                Verify: $"docker pull {host}/library/alpine:3.20",
                Caveats: Caveats(httpCaveat)),

            new(Variant: "docker", OperationPublish, ScopeGlobal, PresetPush,
                Files: daemonFile,
                TokenDelivery: SetupTokenDelivery.FromCommand($"echo <token> | docker login {host} --username user --password-stdin"),
                Verify: $"docker tag <image>:<tag> {host}/<image>:<tag>\ndocker push {host}/<image>:<tag>",
                Caveats: Caveats(httpCaveat)),
        };

        return new SetupRecipesResponse("oci", [new SetupVariant("docker", "Docker")], recipes);
    }

    // ── Go ────────────────────────────────────────────────────────────────────

    private static SetupRecipesResponse Go(string baseUrl)
    {
        string host = HostOf(baseUrl);
        // netrc credentials travel in the clear over plain HTTP.
        string? httpCaveat = IsPlainHttp(baseUrl) ? CaveatCleartextCredentials : null;

        // Go reads ~/.netrc regardless of scope, so even the project recipe points the
        // credential at the home directory rather than at anything committable.
        var netrc = File("~/.netrc", OnEachMachine, "ini",
            $"machine {host} login user password <token>", secretBearing: true);

        // Go is proxy-only — there is no hosted publish path, so no publish recipes exist.
        var recipes = new List<SetupRecipe>
        {
            new(Variant: "go", OperationInstall, ScopeProject, PresetPull,
                Files:
                [
                    File(".envrc", InRepoRoot, "bash",
                        $"export GOPROXY={baseUrl}/go,direct\nexport GOPRIVATE=example.com/private/*\nexport GONOSUMDB=example.com/private/*"),
                    netrc,
                ],
                TokenDelivery: SetupTokenDelivery.Literal(),
                Verify: "direnv allow\ngo env GOPROXY\ngo mod download",
                Caveats: Caveats(httpCaveat)),

            new(Variant: "go", OperationInstall, ScopeGlobal, PresetPull,
                Files: [netrc],
                TokenDelivery: SetupTokenDelivery.Literal(),
                Verify: $"go env -w GOPROXY={baseUrl}/go,direct\ngo env GOPROXY\ngo mod download",
                Caveats: Caveats(httpCaveat)),
        };

        return new SetupRecipesResponse("golang", [new SetupVariant("go", "Go")], recipes);
    }

    // ── RPM ───────────────────────────────────────────────────────────────────

    private static SetupRecipesResponse Rpm(string baseUrl)
    {
        string? httpCaveat = IsPlainHttp(baseUrl) ? CaveatCleartextCredentials : null;

        // A yum/dnf repository is a machine-level file; there is no project scope. gpgcheck
        // stays off until the operator configures signing under Settings > Trust Anchors.
        var recipes = new List<SetupRecipe>
        {
            new(Variant: "dnf", OperationInstall, ScopeGlobal, PresetPull,
                Files:
                [
                    File("/etc/yum.repos.d/dependably.repo", null, "ini",
                        $"[dependably]\nname=dependably\nbaseurl={baseUrl}/rpm/\nenabled=1\ngpgcheck=0\nusername=user\npassword=<token>",
                        secretBearing: true)
                ],
                TokenDelivery: SetupTokenDelivery.Literal(),
                Verify: "dnf clean all\ndnf repolist dependably\ndnf --disablerepo='*' --enablerepo=dependably list available",
                Caveats: Caveats(httpCaveat)),

            new(Variant: "dnf", OperationPublish, ScopeGlobal, PresetPush,
                Files: [],
                TokenDelivery: SetupTokenDelivery.FromCommand(
                    $"curl -u user:<token> --upload-file pkg.rpm {baseUrl}/rpm/upload"),
                Verify: "dnf clean all\ndnf --disablerepo='*' --enablerepo=dependably list available",
                Caveats: Caveats(httpCaveat)),
        };

        return new SetupRecipesResponse("rpm", [new SetupVariant("dnf", "dnf / yum")], recipes);
    }

    // ── Alpine apk ────────────────────────────────────────────────────────────

    private static SetupRecipesResponse Apk(string baseUrl)
    {
        var uri = new Uri(baseUrl);
        // Credentials carried in the URL userinfo — the apk client's only auth mechanism.
        string userinfoUrl = $"{uri.Scheme}://user:<token>@{uri.Authority}/apk";
        string? httpCaveat = IsPlainHttp(baseUrl) ? CaveatCleartextCredentials : null;

        // apk is proxy-only, so there is no publish recipe.
        var recipes = new List<SetupRecipe>
        {
            new(Variant: "apk", OperationInstall, ScopeGlobal, PresetPull,
                Files:
                [
                    File("/etc/apk/repositories", null, "ini",
                        $"{userinfoUrl}/v3.22/main\n{userinfoUrl}/v3.22/community",
                        secretBearing: true)
                ],
                TokenDelivery: SetupTokenDelivery.Literal(),
                Verify: "apk update\napk policy busybox",
                Caveats: Caveats(httpCaveat)),
        };

        return new SetupRecipesResponse("apk", [new SetupVariant("apk", "Alpine apk")], recipes);
    }

    // ── Terraform ─────────────────────────────────────────────────────────────

    private static SetupRecipesResponse Terraform(string baseUrl)
    {
        var uri = new Uri(baseUrl);
        string userinfoUrl = $"{uri.Scheme}://user:<token>@{uri.Authority}/terraform/";
        // Terraform rejects an http:// network-mirror URL while parsing the file, before any
        // request is made, so on a plain-HTTP deployment this recipe cannot work at all —
        // there is no client-side override, only terminating TLS in front of Dependably.
        string? httpCaveat = IsPlainHttp(baseUrl) ? CaveatHttpMirror : null;

        // provider_installation is CLI-level configuration and applies to every provider a
        // configuration requests, so there is no per-repository file. Terraform is proxy-only.
        var recipes = new List<SetupRecipe>
        {
            new(Variant: "terraform", OperationInstall, ScopeGlobal, PresetPull,
                Files:
                [
                    File("~/.terraformrc", InHomeDir, "hcl",
                        $"provider_installation {{\n  network_mirror {{\n    url = \"{userinfoUrl}\"\n  }}\n}}",
                        secretBearing: true)
                ],
                TokenDelivery: SetupTokenDelivery.Literal(),
                // Existing .terraform.lock.hcl files keep working: Terraform recomputes each
                // provider's h1 hash from the archive it downloads and verifies it against the lock.
                Verify: "terraform init\nterraform providers",
                Caveats: Caveats(httpCaveat)),
        };

        return new SetupRecipesResponse("terraform", [new SetupVariant("terraform", "Terraform")], recipes);
    }
}
