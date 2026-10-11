using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Tests;

public sealed class IncidentCreationContractTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private readonly HttpClient _client = factory.CreateClient();

    [Fact]
    public async Task Create_WithMissingRequiredFields_Returns400ProblemDetails()
    {
        using var response = await PostCreateAsync(new { });

        await AssertValidationProblemAsync(
            response,
            "title",
            "description",
            "severity",
            "occurredAtUtc");
    }

    [Fact]
    public async Task Create_WithTitleLongerThan160Characters_Returns400()
    {
        using var response = await PostCreateAsync(new
        {
            title = new string('t', 161),
            description = "Коректний опис.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow
        });

        await AssertValidationProblemAsync(response, "title");
    }

    [Fact]
    public async Task Create_WithDescriptionLongerThan4000Characters_Returns400()
    {
        using var response = await PostCreateAsync(new
        {
            title = "Перевірка максимальної довжини опису",
            description = new string('d', 4001),
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow
        });

        await AssertValidationProblemAsync(response, "description");
    }

    [Fact]
    public async Task Create_WithNumericSeverity_Returns400ProblemDetails()
    {
        using var response = await PostCreateAsync(new
        {
            title = "Перевірка числового severity",
            description = "Коректний опис для перевірки severity.",
            severity = "7",
            occurredAtUtc = DateTimeOffset.UtcNow
        });

        await AssertValidationProblemAsync(response, "severity");
    }

    [Fact]
    public async Task Create_WithCombinedSeverityNames_Returns400ProblemDetails()
    {
        Guid? createdIncidentId = null;

        try
        {
            using var response = await PostCreateAsync(new
            {
                title = "Перевірка комбінованого severity",
                description = "Коректний опис для перевірки формату severity.",
                severity = "Low,High",
                occurredAtUtc = DateTimeOffset.UtcNow
            });

            // A regression must not leave a record behind merely because this
            // test correctly detects that the endpoint returned 201 by mistake.
            if (response.StatusCode == HttpStatusCode.Created)
            {
                using var document = JsonDocument.Parse(
                    await response.Content.ReadAsStringAsync());

                createdIncidentId = document.RootElement
                    .GetProperty("id")
                    .GetGuid();
            }

            await AssertValidationProblemAsync(response, "severity");
        }
        finally
        {
            if (createdIncidentId is Guid id)
            {
                using var scope = factory.Services.CreateScope();
                var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();

                await db.Incidents
                    .Where(item => item.Id == id)
                    .ExecuteDeleteAsync();
            }
        }
    }

    [Fact]
    public async Task Create_WithoutOccurredAtUtc_Returns400ProblemDetails()
    {
        using var response = await PostCreateAsync(new
        {
            title = "Перевірка обов’язкової дати",
            description = "Коректний опис для перевірки дати.",
            severity = "Low"
        });

        await AssertValidationProblemAsync(response, "occurredAtUtc");
    }

    [Fact]
    public async Task Create_WithDateMoreThanFiveMinutesInFuture_Returns400()
    {
        using var response = await PostCreateAsync(new
        {
            title = "Перевірка майбутньої дати",
            description = "Коректний опис для перевірки дати.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(10)
        });

        await AssertValidationProblemAsync(response, "occurredAtUtc");
    }

    [Fact]
    public async Task Create_WithNonUtcOffset_NormalizesOccurredAtUtcToUtc()
    {
        var title = $"Часовий пояс {Guid.NewGuid():N}";
        var suppliedOccurredAt = new DateTimeOffset(
            2026,
            8,
            10,
            13,
            0,
            0,
            TimeSpan.FromHours(3));

        Guid? createdIncidentId = null;

        try
        {
            using var response = await PostCreateAsync(new
            {
                title,
                description =
                    "Опис для перевірки нормалізації часового зсуву до UTC.",
                severity = "Low",
                occurredAtUtc = suppliedOccurredAt
            });

            Assert.Equal(HttpStatusCode.Created, response.StatusCode);

            using var document = JsonDocument.Parse(
                await response.Content.ReadAsStringAsync());

            var root = document.RootElement;

            createdIncidentId = root
                .GetProperty("id")
                .GetGuid();

            Assert.Equal(
                suppliedOccurredAt.ToUniversalTime(),
                root.GetProperty("occurredAtUtc")
                    .GetDateTimeOffset());

            using var scope = factory.Services.CreateScope();

            var db = scope.ServiceProvider
                .GetRequiredService<SecureLabDbContext>();

            var stored = await db.Incidents
                .AsNoTracking()
                .SingleAsync(
                    item => item.Id == createdIncidentId);

            Assert.Equal(
                suppliedOccurredAt.ToUniversalTime(),
                stored.OccurredAtUtc);

            Assert.Equal(
                TimeSpan.Zero,
                stored.OccurredAtUtc.Offset);
        }
        finally
        {
            if (createdIncidentId is Guid id)
            {
                using var cleanupScope =
                    factory.Services.CreateScope();

                var db = cleanupScope.ServiceProvider
                    .GetRequiredService<SecureLabDbContext>();

                await db.Incidents
                    .Where(item => item.Id == id)
                    .ExecuteDeleteAsync();
            }
        }
    }

    [Fact]
    public async Task Create_HighWith39CharactersAfterTrim_Returns400()
    {
        using var response = await PostCreateAsync(new
        {
            title = $"High short {Guid.NewGuid():N}",
            description = $"  {new string('x', 39)}  ",
            severity = "High",
            occurredAtUtc = DateTimeOffset.UtcNow
        });

        await AssertValidationProblemAsync(
            response,
            "description");
    }

    [Fact]
    public async Task Create_HighWith40CharactersAfterTrim_Returns201AndUsesServerFields()
    {
        var normalizedTitle =
            $"High valid {Guid.NewGuid():N}";

        Guid? createdIncidentId = null;

        try
        {
            using var response = await PostCreateAsync(new
            {
                title = $"  {normalizedTitle}  ",
                description = $"  {new string('x', 40)}  ",
                severity = "High",
                occurredAtUtc = DateTimeOffset.UtcNow,

                // Навмисно зайві server-managed поля.
                ownerUserId = Guid.NewGuid(),
                status = "Closed"
            });

            Assert.Equal(
                HttpStatusCode.Created,
                response.StatusCode);

            Assert.Equal(
                "application/json",
                response.Content.Headers.ContentType?.MediaType);

            using var document = JsonDocument.Parse(
                await response.Content.ReadAsStringAsync());

            var root = document.RootElement;

            Assert.Equal(
                normalizedTitle,
                root.GetProperty("title").GetString());

            Assert.Equal(
                "High",
                root.GetProperty("severity").GetString());

            Assert.Equal(
                "New",
                root.GetProperty("status").GetString());

            Assert.True(
                root.TryGetProperty(
                    "occurredAtUtc",
                    out _));

            Assert.True(
                root.TryGetProperty(
                    "createdAtUtc",
                    out _));

            Assert.False(
                root.TryGetProperty(
                    "description",
                    out _));

            Assert.False(
                root.TryGetProperty(
                    "ownerUserId",
                    out _));

            Assert.False(
                root.TryGetProperty(
                    "updatedAtUtc",
                    out _));

            createdIncidentId = root
                .GetProperty("id")
                .GetGuid();

            using var detailsResponse =
                await _client.GetAsync(
                    $"/api/incidents/{createdIncidentId}");

            Assert.Equal(
                HttpStatusCode.OK,
                detailsResponse.StatusCode);

            using var detailsDocument = JsonDocument.Parse(
                await detailsResponse.Content.ReadAsStringAsync());

            Assert.Equal(
                "New",
                detailsDocument.RootElement
                    .GetProperty("status")
                    .GetString());

            Assert.False(
                detailsDocument.RootElement
                    .TryGetProperty(
                        "ownerUserId",
                        out _));
        }
        finally
        {
            if (createdIncidentId is Guid id)
            {
                using var cleanupScope =
                    factory.Services.CreateScope();

                var db = cleanupScope.ServiceProvider
                    .GetRequiredService<SecureLabDbContext>();

                await db.Incidents
                    .Where(item => item.Id == id)
                    .ExecuteDeleteAsync();
            }
        }
    }

    // ================================================================
    // A-02 — OVERPOSTING / MASS ASSIGNMENT
    //
    // Клієнт навмисно надсилає server-managed поля:
    // id, ownerUserId, status, createdAtUtc.
    //
    // CreateIncidentRequest не повинен дозволяти клієнту
    // керувати цими значеннями.
    //
    // Очікується:
    // - сервер генерує новий Id;
    // - OwnerUserId = DbSeeder.AliceId;
    // - Status = New;
    // - CreatedAtUtc встановлює сервер;
    // - запису з нав'язаним клієнтом Id у БД немає;
    // - GET показує ownerDisplayName = "Аліса Коваль".
    // ================================================================

    [Fact]
    public async Task Create_IgnoresClientSuppliedServerManagedFields()
    {
        var clientSuppliedId =
            Guid.Parse(
                "11111111-1111-1111-1111-111111111111");

        var clientSuppliedOwnerId =
            Guid.Parse(
                "22222222-2222-2222-2222-222222222222");

        var clientSuppliedCreatedAtUtc =
            DateTimeOffset.UtcNow.AddYears(-5);

        var title =
            $"MassAssign-{Guid.NewGuid():N}";

        Guid? createdIncidentId = null;

        var beforeRequestUtc =
            DateTimeOffset.UtcNow;

        try
        {
            using var response = await PostCreateAsync(new
            {
                // Поля, якими клієнт не повинен керувати.
                id = clientSuppliedId,
                ownerUserId = clientSuppliedOwnerId,
                status = "Closed",
                createdAtUtc = clientSuppliedCreatedAtUtc,

                // Дозволені поля CreateIncidentRequest.
                title,
                description =
                    "Опис для перевірки mass assignment на створенні інциденту.",
                severity = "Low",
                occurredAtUtc = DateTimeOffset.UtcNow
            });

            var afterRequestUtc =
                DateTimeOffset.UtcNow;

            // --------------------------------------------------------
            // 1. POST response
            // --------------------------------------------------------

            Assert.Equal(
                HttpStatusCode.Created,
                response.StatusCode);

            Assert.Equal(
                "application/json",
                response.Content.Headers
                    .ContentType?.MediaType);

            var body =
                await response.Content.ReadAsStringAsync();

            using var document =
                JsonDocument.Parse(body);

            var root =
                document.RootElement;

            var createdId =
                root.GetProperty("id").GetGuid();

            createdIncidentId =
                createdId;

            // Нав'язаний Id має бути проігноровано.
            Assert.NotEqual(
                clientSuppliedId,
                createdId);

            // Нав'язаний Closed має бути проігноровано.
            Assert.Equal(
                "New",
                root.GetProperty("status").GetString());

            // CreatedAtUtc має бути серверним.
            var responseCreatedAtUtc =
                root.GetProperty("createdAtUtc")
                    .GetDateTimeOffset();

            Assert.NotEqual(
                clientSuppliedCreatedAtUtc,
                responseCreatedAtUtc);

            Assert.InRange(
                responseCreatedAtUtc,
                beforeRequestUtc.AddSeconds(-1),
                afterRequestUtc.AddSeconds(1));

            // Внутрішній FK власника не повертається.
            Assert.False(
                root.TryGetProperty(
                    "ownerUserId",
                    out _));

            // --------------------------------------------------------
            // 2. Фактичний запис у БД
            // --------------------------------------------------------

            using (var scope =
                   factory.Services.CreateScope())
            {
                var db = scope.ServiceProvider
                    .GetRequiredService<SecureLabDbContext>();

                var stored = await db.Incidents
                    .AsNoTracking()
                    .SingleAsync(
                        item => item.Id == createdId);

                // Серверний Id.
                Assert.NotEqual(
                    clientSuppliedId,
                    stored.Id);

                // Серверний власник Alice.
                Assert.Equal(
                    DbSeeder.AliceId,
                    stored.OwnerUserId);

                Assert.NotEqual(
                    clientSuppliedOwnerId,
                    stored.OwnerUserId);

                // Серверний Status.
                Assert.Equal(
                    IncidentStatus.New,
                    stored.Status);

                // Серверний CreatedAtUtc.
                Assert.NotEqual(
                    clientSuppliedCreatedAtUtc,
                    stored.CreatedAtUtc);

                Assert.InRange(
                    stored.CreatedAtUtc,
                    beforeRequestUtc.AddSeconds(-1),
                    afterRequestUtc.AddSeconds(1));

                // Запису з нав'язаним клієнтським Id немає.
                Assert.False(
                    await db.Incidents.AnyAsync(
                        item => item.Id == clientSuppliedId));
            }

            // --------------------------------------------------------
            // 3. Перевірка через публічний GET endpoint
            // --------------------------------------------------------

            using var detailsResponse =
                await _client.GetAsync(
                    $"/api/incidents/{createdId}");

            Assert.Equal(
                HttpStatusCode.OK,
                detailsResponse.StatusCode);

            Assert.Equal(
                "application/json",
                detailsResponse.Content.Headers
                    .ContentType?.MediaType);

            using var detailsDocument =
                JsonDocument.Parse(
                    await detailsResponse.Content
                        .ReadAsStringAsync());

            var details =
                detailsDocument.RootElement;

            Assert.Equal(
                "New",
                details.GetProperty("status")
                    .GetString());

            // Власника призначив сервер.
            Assert.Equal(
                "Аліса Коваль",
                details.GetProperty("ownerDisplayName")
                    .GetString());

            // Внутрішній FK не розкривається клієнту.
            Assert.False(
                details.TryGetProperty(
                    "ownerUserId",
                    out _));
        }
        finally
        {
            // --------------------------------------------------------
            // Cleanup створеного сервером запису.
            // --------------------------------------------------------

            if (createdIncidentId is Guid id)
            {
                using var cleanupScope =
                    factory.Services.CreateScope();

                var cleanupDb =
                    cleanupScope.ServiceProvider
                        .GetRequiredService<SecureLabDbContext>();

                await cleanupDb.Incidents
                    .Where(item => item.Id == id)
                    .ExecuteDeleteAsync();
            }

            // Defensive cleanup:
            // якщо реалізація помилково прийняла clientSuppliedId,
            // тест усе одно не залишить зайвий запис у БД.
            using var defensiveCleanupScope =
                factory.Services.CreateScope();

            var defensiveCleanupDb =
                defensiveCleanupScope.ServiceProvider
                    .GetRequiredService<SecureLabDbContext>();

            await defensiveCleanupDb.Incidents
                .Where(item => item.Id == clientSuppliedId)
                .ExecuteDeleteAsync();
        }
    }

    [Fact]
    public async Task Create_WithTrimmedTitleMatchingActiveSeedIncident_Returns409ProblemDetails()
    {
        using var response = await PostCreateAsync(new
        {
            title =
                "  Підозрілий лист із вкладенням  ",
            description =
                "Повторна спроба створити інцидент із наявною активною назвою.",
            severity = "Medium",
            occurredAtUtc = DateTimeOffset.UtcNow
        });

        Assert.Equal(
            HttpStatusCode.Conflict,
            response.StatusCode);

        Assert.Equal(
            "application/problem+json",
            response.Content.Headers.ContentType?.MediaType);

        var body =
            await response.Content.ReadAsStringAsync();

        Assert.Contains(
            "Активний інцидент із такою назвою вже зареєстровано.",
            body);

        Assert.DoesNotContain(
            "Npgsql",
            body,
            StringComparison.OrdinalIgnoreCase);

        Assert.DoesNotContain(
            "SecureLab.Api.Data",
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

        Assert.DoesNotContain(
            "sqlstate",
            body,
            StringComparison.OrdinalIgnoreCase);

        Assert.DoesNotContain(
            "select ",
            body,
            StringComparison.OrdinalIgnoreCase);

        Assert.DoesNotContain(
            "from incidents",
            body,
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Create_WithSameGeneratedTitle_Returns201Then409()
    {
        var title =
            $"Regression-{Guid.NewGuid():N}";

        Guid? createdIncidentId = null;

        try
        {
            using (var firstResponse =
                   await PostCreateAsync(new
                   {
                       title,
                       description =
                           "Перший коректний інцидент для перевірки повторного створення.",
                       severity = "Medium",
                       occurredAtUtc = DateTimeOffset.UtcNow
                   }))
            {
                Assert.Equal(
                    HttpStatusCode.Created,
                    firstResponse.StatusCode);

                using var firstDocument =
                    JsonDocument.Parse(
                        await firstResponse.Content
                            .ReadAsStringAsync());

                createdIncidentId =
                    firstDocument.RootElement
                        .GetProperty("id")
                        .GetGuid();
            }

            using var secondResponse =
                await PostCreateAsync(new
                {
                    title = $"  {title}  ",
                    description =
                        "Повторна спроба з тим самим нормалізованим заголовком.",
                    severity = "Medium",
                    occurredAtUtc = DateTimeOffset.UtcNow
                });

            Assert.Equal(
                HttpStatusCode.Conflict,
                secondResponse.StatusCode);

            Assert.Equal(
                "application/problem+json",
                secondResponse.Content.Headers
                    .ContentType?.MediaType);
        }
        finally
        {
            if (createdIncidentId is Guid id)
            {
                using var cleanupScope =
                    factory.Services.CreateScope();

                var db = cleanupScope.ServiceProvider
                    .GetRequiredService<SecureLabDbContext>();

                await db.Incidents
                    .Where(item => item.Id == id)
                    .ExecuteDeleteAsync();
            }
        }
    }

    [Fact]
    public async Task Create_WithTitleMatchingClosedIncident_Returns201()
    {
        var title =
            $"Closed incident {Guid.NewGuid():N}";

        var closedIncidentId =
            Guid.NewGuid();

        Guid? createdIncidentId = null;

        using (var setupScope =
               factory.Services.CreateScope())
        {
            var db = setupScope.ServiceProvider
                .GetRequiredService<SecureLabDbContext>();

            var now =
                DateTimeOffset.UtcNow;

            db.Incidents.Add(new Incident
            {
                Id = closedIncidentId,
                OwnerUserId = DbSeeder.AliceId,
                Title = title,
                Description =
                    "Закритий інцидент для перевірки предметного правила.",
                Severity = IncidentSeverity.Low,
                Status = IncidentStatus.Closed,
                OccurredAtUtc = now,
                CreatedAtUtc = now,
                UpdatedAtUtc = now
            });

            await db.SaveChangesAsync();
        }

        try
        {
            using var response =
                await PostCreateAsync(new
                {
                    title = $"  {title}  ",
                    description =
                        "Новий інцидент з title, який має збіг лише з Closed записом.",
                    severity = "Medium",
                    occurredAtUtc = DateTimeOffset.UtcNow
                });

            Assert.Equal(
                HttpStatusCode.Created,
                response.StatusCode);

            using var document =
                JsonDocument.Parse(
                    await response.Content
                        .ReadAsStringAsync());

            createdIncidentId =
                document.RootElement
                    .GetProperty("id")
                    .GetGuid();
        }
        finally
        {
            using var cleanupScope =
                factory.Services.CreateScope();

            var db = cleanupScope.ServiceProvider
                .GetRequiredService<SecureLabDbContext>();

            if (createdIncidentId is Guid id)
            {
                await db.Incidents
                    .Where(item => item.Id == id)
                    .ExecuteDeleteAsync();
            }

            await db.Incidents
                .Where(item => item.Id == closedIncidentId)
                .ExecuteDeleteAsync();
        }
    }

    [Fact]
    public async Task Create_WithTitleDifferingOnlyByCase_Returns201()
    {
        var existingTitle =
            $"Alert-{Guid.NewGuid():N}";

        var requestedTitle =
            existingTitle.ToLowerInvariant();

        var existingIncidentId =
            Guid.NewGuid();

        Guid? createdIncidentId = null;

        using (var setupScope =
               factory.Services.CreateScope())
        {
            var db = setupScope.ServiceProvider
                .GetRequiredService<SecureLabDbContext>();

            var now =
                DateTimeOffset.UtcNow;

            db.Incidents.Add(new Incident
            {
                Id = existingIncidentId,
                OwnerUserId = DbSeeder.AliceId,
                Title = existingTitle,
                Description =
                    "Активний інцидент для перевірки чутливості title до регістру.",
                Severity = IncidentSeverity.Low,
                Status = IncidentStatus.New,
                OccurredAtUtc = now,
                CreatedAtUtc = now,
                UpdatedAtUtc = now
            });

            await db.SaveChangesAsync();
        }

        try
        {
            using var response =
                await PostCreateAsync(new
                {
                    title = $"  {requestedTitle}  ",
                    description =
                        "Новий інцидент відрізняється від активного title лише регістром.",
                    severity = "Medium",
                    occurredAtUtc = DateTimeOffset.UtcNow
                });

            Assert.Equal(
                HttpStatusCode.Created,
                response.StatusCode);

            using var document =
                JsonDocument.Parse(
                    await response.Content
                        .ReadAsStringAsync());

            Assert.Equal(
                requestedTitle,
                document.RootElement
                    .GetProperty("title")
                    .GetString());

            createdIncidentId =
                document.RootElement
                    .GetProperty("id")
                    .GetGuid();
        }
        finally
        {
            using var cleanupScope =
                factory.Services.CreateScope();

            var db = cleanupScope.ServiceProvider
                .GetRequiredService<SecureLabDbContext>();

            if (createdIncidentId is Guid id)
            {
                await db.Incidents
                    .Where(item => item.Id == id)
                    .ExecuteDeleteAsync();
            }

            await db.Incidents
                .Where(item => item.Id == existingIncidentId)
                .ExecuteDeleteAsync();
        }
    }

    [Theory]
    [InlineData("New")]
    [InlineData("Triaged")]
    [InlineData("InProgress")]
    [InlineData("Resolved")]
    public async Task Create_WithTitleMatchingEachBlockingStatus_Returns409(
        string statusText)
    {
        var title =
            $"Blocking-{statusText}-{Guid.NewGuid():N}";

        var existingIncidentId =
            Guid.NewGuid();

        using (var setupScope =
               factory.Services.CreateScope())
        {
            var db = setupScope.ServiceProvider
                .GetRequiredService<SecureLabDbContext>();

            var now =
                DateTimeOffset.UtcNow;

            db.Incidents.Add(new Incident
            {
                Id = existingIncidentId,
                OwnerUserId = DbSeeder.AliceId,
                Title = title,
                Description =
                    "Активний інцидент для перевірки блокувального статусу.",
                Severity = IncidentSeverity.Low,
                Status = Enum.Parse<IncidentStatus>(
                    statusText),
                OccurredAtUtc = now,
                CreatedAtUtc = now,
                UpdatedAtUtc = now
            });

            await db.SaveChangesAsync();
        }

        try
        {
            using var response =
                await PostCreateAsync(new
                {
                    title = $"  {title}  ",
                    description =
                        "Повторне створення має блокуватися активним статусом.",
                    severity = "Medium",
                    occurredAtUtc = DateTimeOffset.UtcNow
                });

            Assert.Equal(
                HttpStatusCode.Conflict,
                response.StatusCode);
        }
        finally
        {
            using var cleanupScope =
                factory.Services.CreateScope();

            var db = cleanupScope.ServiceProvider
                .GetRequiredService<SecureLabDbContext>();

            await db.Incidents
                .Where(
                    item =>
                        item.Id == existingIncidentId)
                .ExecuteDeleteAsync();
        }
    }

    // ================================================================
    // T-10 — додаткова нетривіальна предметна перевірка
    //
    // Правило:
    // description після Trim() не може повністю дорівнювати
    // title після Trim().
    //
    // Порушення:
    // 400 Bad Request + errors.description.
    //
    // Допустимий стан:
    // description містить додаткові факти -> 201 Created.
    // ================================================================

    [Fact]
    public async Task Create_WhenDescriptionEqualsTitleAfterTrim_Returns400()
    {
        var title =
            $"Same text {Guid.NewGuid():N}";

        using var response =
            await PostCreateAsync(new
            {
                title = $"  {title}  ",
                description = $"  {title}  ",
                severity = "Low",
                occurredAtUtc = DateTimeOffset.UtcNow
            });

        await AssertValidationProblemAsync(
            response,
            "description");
    }

    [Fact]
    public async Task Create_WhenDescriptionAddsDetails_Returns201()
    {
        var title =
            $"T10 title {Guid.NewGuid():N}";

        Guid? createdIncidentId = null;

        try
        {
            using var response =
                await PostCreateAsync(new
                {
                    title,
                    description =
                        "Опис містить додаткові факти, яких немає в заголовку інциденту.",
                    severity = "Low",
                    occurredAtUtc = DateTimeOffset.UtcNow
                });

            Assert.Equal(
                HttpStatusCode.Created,
                response.StatusCode);

            using var document =
                JsonDocument.Parse(
                    await response.Content
                        .ReadAsStringAsync());

            createdIncidentId =
                document.RootElement
                    .GetProperty("id")
                    .GetGuid();
        }
        finally
        {
            if (createdIncidentId is Guid id)
            {
                using var cleanupScope =
                    factory.Services.CreateScope();

                var db = cleanupScope.ServiceProvider
                    .GetRequiredService<SecureLabDbContext>();

                await db.Incidents
                    .Where(item => item.Id == id)
                    .ExecuteDeleteAsync();
            }
        }
    }

    private async Task<HttpResponseMessage> PostCreateAsync(
        object request)
    {
        using var client = await factory.LoginAsync(
            "alice",
            GetLocalStudyPassword());

        return await client.PostAsJsonAsync(
            "/api/incidents",
            request);
    }

    private static string GetLocalStudyPassword() =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private static async Task AssertValidationProblemAsync(
        HttpResponseMessage response,
        params string[] expectedErrorFields)
    {
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

        foreach (var field in expectedErrorFields)
        {
            Assert.True(
                errors.TryGetProperty(
                    field,
                    out _),
                $"Відсутня помилка поля '{field}'.");
        }

        // Problem Details не повинен розкривати
        // внутрішні деталі реалізації та БД.
        Assert.DoesNotContain(
            "Npgsql",
            body,
            StringComparison.OrdinalIgnoreCase);

        Assert.DoesNotContain(
            "SecureLab.Api.Data",
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

        Assert.DoesNotContain(
            "sqlstate",
            body,
            StringComparison.OrdinalIgnoreCase);

        Assert.DoesNotContain(
            "select ",
            body,
            StringComparison.OrdinalIgnoreCase);

        Assert.DoesNotContain(
            "from incidents",
            body,
            StringComparison.OrdinalIgnoreCase);
    }
}
