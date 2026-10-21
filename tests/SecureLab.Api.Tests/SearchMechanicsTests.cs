using System.Net;
using System.Text.Json;
using SecureLab.Api.Data;
using SecureLab.Api.Scaffolding;

namespace SecureLab.Api.Tests;

public sealed class SearchMechanicsTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    [Fact]
    public async Task Search_ReturnsJson()
    {
        using var client = await CreateAnalystClientAsync();

        using var response =
            await client.GetAsync(
                "/api/incidents/search?q=навчальн");

        Assert.Equal(
            HttpStatusCode.OK,
            response.StatusCode);

        Assert.Equal(
            "application/json",
            response.Content.Headers
                .ContentType?.MediaType);
    }

    // ================================================================
    // Positive exact-set control:
    // звичайний USB-пошук повертає рівно один очікуваний seed.
    // ================================================================
    [Fact]
    public async Task Search_WithNormalUsbQuery_ReturnsOnlyUsbSeedIncident()
    {
        using var client = await CreateAnalystClientAsync();

        using var response =
            await client.GetAsync(
                "/api/incidents/search?q=USB");

        Assert.Equal(
            HttpStatusCode.OK,
            response.StatusCode);

        using var document =
            JsonDocument.Parse(
                await response.Content.ReadAsStringAsync());

        var rows = document.RootElement;

        Assert.Equal(
            JsonValueKind.Array,
            rows.ValueKind);

        var actualIds =
            ReadResultIds(rows);

        Assert.True(
            actualIds.SetEquals(
                [Lab02Seed.UsbIncidentId]),
            "USB-пошук має повертати рівно один штатний USB seed-запис.");
    }

    // ================================================================
    // S-02 — автоматичний security regression для "Відмінно".
    //
    // Перевіряється не лише HTTP 200,
    // а точна множина результатів: порожня.
    // ================================================================
    [Fact]
    public async Task Search_WithControlledReadOnlyInput_ReturnsNoMatches()
    {
        using var client = await CreateAnalystClientAsync();

        using var response =
            await client.GetAsync(
                "/api/incidents/search?q=zz-no-match%27%20OR%20TRUE%20--%20");

        Assert.Equal(
            HttpStatusCode.OK,
            response.StatusCode);

        using var document =
            JsonDocument.Parse(
                await response.Content.ReadAsStringAsync());

        Assert.Equal(
            JsonValueKind.Array,
            document.RootElement.ValueKind);

        var actualIds =
            ReadResultIds(
                document.RootElement);

        Assert.True(
            actualIds.SetEquals([]),
            "S-02 має доводити точну порожню множину без зайвих або чужих записів.");
    }

    // ================================================================
    // T-04 — позитивна регресія:
    // легітимне слово з апострофом повинно працювати.
    // ================================================================
    [Fact]
    public async Task Search_WithLegitimateApostrophe_ReturnsMatchingSeedIncident()
    {
        using var client = await CreateAnalystClientAsync();

        using var response =
            await client.GetAsync(
                "/api/incidents/search?q=%D0%BA%D0%BE%D0%BC%D0%BF%27%D1%8E%D1%82%D0%B5%D1%80%D0%BD%D0%BE%D0%B3%D0%BE");

        Assert.Equal(
            HttpStatusCode.OK,
            response.StatusCode);

        using var document =
            JsonDocument.Parse(
                await response.Content.ReadAsStringAsync());

        var actualIds =
            ReadResultIds(
                document.RootElement);

        Assert.True(
            actualIds.SetEquals(
                [Lab02Seed.ComputerClassroomIncidentId]),
            "Пошук легітимного слова з апострофом має повертати тільки відповідний seed-запис.");
    }

    // ================================================================
    // Literal substring:
    // % від клієнта не повинен перетворюватися на LIKE wildcard.
    // ================================================================
    [Fact]
    public async Task Search_WithPercentSign_SearchesForLiteralPercentAndReturnsNoMatches()
    {
        using var client = await CreateAnalystClientAsync();

        using var response =
            await client.GetAsync(
                "/api/incidents/search?q=%25");

        Assert.Equal(
            HttpStatusCode.OK,
            response.StatusCode);

        using var document =
            JsonDocument.Parse(
                await response.Content.ReadAsStringAsync());

        var actualIds =
            ReadResultIds(
                document.RootElement);

        Assert.True(
            actualIds.SetEquals([]),
            "Percent sign must not work as a LIKE wildcard supplied by the client.");
    }

    // ================================================================
    // T-05 — невідомий sortBy:
    // 400 Problem Details + errors.sortBy.
    // ================================================================
    [Fact]
    public async Task Search_WithUnsupportedSortBy_Returns400ProblemDetails()
    {
        using var client = await CreateAnalystClientAsync();

        using var response =
            await client.GetAsync(
                "/api/incidents/search?q=USB&sortBy=unknown");

        Assert.Equal(
            HttpStatusCode.BadRequest,
            response.StatusCode);

        Assert.Equal(
            "application/problem+json",
            response.Content.Headers
                .ContentType?.MediaType);

        var body =
            await response.Content.ReadAsStringAsync();

        using var document =
            JsonDocument.Parse(body);

        var errors =
            document.RootElement
                .GetProperty("errors");

        Assert.True(
            errors.TryGetProperty(
                "sortBy",
                out _));

        // Не розкриваємо внутрішні деталі.
        Assert.DoesNotContain(
            "Npgsql",
            body,
            StringComparison.OrdinalIgnoreCase);

        Assert.DoesNotContain(
            "stack trace",
            body,
            StringComparison.OrdinalIgnoreCase);

        Assert.DoesNotContain(
            "connection string",
            body,
            StringComparison.OrdinalIgnoreCase);
    }

    // ================================================================
    // Default:
    // CreatedAtUtc DESC,
    // другий ключ Id.
    //
    // Очікуваний seed:
    // 0004 -> 0005 -> 0003 -> 0002 -> 0001
    // ================================================================
    [Fact]
    public async Task Search_WithoutSortBy_OrdersByCreatedAtUtcDescendingThenId()
    {
        using var client = await CreateAnalystClientAsync();

        using var response =
            await client.GetAsync(
                "/api/incidents/search?q=");

        Assert.Equal(
            HttpStatusCode.OK,
            response.StatusCode);

        using var document =
            JsonDocument.Parse(
                await response.Content.ReadAsStringAsync());

        Assert.Equal(
        [
            Guid.Parse(
                "20000000-0000-0000-0000-000000000004"),

            Lab02Seed.UsbIncidentId,

            Lab02Seed.ComputerClassroomIncidentId,

            DbSeeder.BobIncidentId,

            DbSeeder.AliceIncidentId
        ],
        ReadOrderedResultIds(
            document.RootElement));
    }

    // ================================================================
    // severity:
    // Critical -> High -> Medium -> Low,
    // потім Id.
    //
    // У штатному seed Critical немає:
    // 0002 High -> 0001 Medium -> 0003/0004/0005 Low.
    // ================================================================
    [Fact]
    public async Task Search_WithSeveritySort_OrdersByBusinessRankThenId()
    {
        using var client = await CreateAnalystClientAsync();

        using var response =
            await client.GetAsync(
                "/api/incidents/search?q=&sortBy=severity");

        Assert.Equal(
            HttpStatusCode.OK,
            response.StatusCode);

        using var document =
            JsonDocument.Parse(
                await response.Content.ReadAsStringAsync());

        Assert.Equal(
        [
            DbSeeder.BobIncidentId,

            DbSeeder.AliceIncidentId,

            Lab02Seed.ComputerClassroomIncidentId,

            Guid.Parse(
                "20000000-0000-0000-0000-000000000004"),

            Lab02Seed.UsbIncidentId
        ],
        ReadOrderedResultIds(
            document.RootElement));
    }

    // ================================================================
    // status:
    // New -> Triaged -> InProgress -> Resolved -> Closed,
    // потім Id.
    //
    // Штатний seed:
    // 0003/0004/0005 New -> 0001 Triaged -> 0002 InProgress.
    // ================================================================
    [Fact]
    public async Task Search_WithStatusSort_OrdersByBusinessRankThenId()
    {
        using var client = await CreateAnalystClientAsync();

        using var response =
            await client.GetAsync(
                "/api/incidents/search?q=&sortBy=status");

        Assert.Equal(
            HttpStatusCode.OK,
            response.StatusCode);

        using var document =
            JsonDocument.Parse(
                await response.Content.ReadAsStringAsync());

        Assert.Equal(
        [
            Lab02Seed.ComputerClassroomIncidentId,

            Guid.Parse(
                "20000000-0000-0000-0000-000000000004"),

            Lab02Seed.UsbIncidentId,

            DbSeeder.AliceIncidentId,

            DbSeeder.BobIncidentId
        ],
        ReadOrderedResultIds(
            document.RootElement));
    }

    // ================================================================
    // Allowlist:
    // усі три дозволені значення повинні працювати.
    // ================================================================
    [Theory]
    [InlineData("createdAtUtc")]
    [InlineData("severity")]
    [InlineData("status")]
    public async Task Search_WithAllowedSortBy_ReturnsJson(
        string sortBy)
    {
        using var client = await CreateAnalystClientAsync();

        using var response =
            await client.GetAsync(
                $"/api/incidents/search?q=%D0%BD%D0%B0%D0%B2%D1%87%D0%B0%D0%BB%D1%8C%D0%BD&sortBy={sortBy}");

        Assert.Equal(
            HttpStatusCode.OK,
            response.StatusCode);

        Assert.Equal(
            "application/json",
            response.Content.Headers
                .ContentType?.MediaType);
    }

    private Task<HttpClient> CreateAnalystClientAsync() =>
        factory.LoginAsync("morgan", Environment.GetEnvironmentVariable("SeedUsers__Password")
            ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git."));

    private static HashSet<Guid> ReadResultIds(
        JsonElement rows) =>
        rows
            .EnumerateArray()
            .Select(
                row =>
                    row.GetProperty("id")
                        .GetGuid())
            .ToHashSet();

    private static Guid[] ReadOrderedResultIds(
        JsonElement rows) =>
        rows
            .EnumerateArray()
            .Select(
                row =>
                    row.GetProperty("id")
                        .GetGuid())
            .ToArray();
}
