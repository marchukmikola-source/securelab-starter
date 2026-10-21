using SecureLab.Api.Scaffolding;
using Microsoft.EntityFrameworkCore;
using Scalar.AspNetCore;
using SecureLab.Api.Application.Authentication;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data;
using SecureLab.Api.Presentation.Endpoints;

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args,
    WebRootPath = "Client"
});
builder.Services.AddOpenApi();
builder.Services.AddProblemDetails();

if (builder.Environment.IsDevelopment())
{
    builder.Services.AddCors(options =>
    {
        options.AddPolicy("Lab05BrowserProbe", policy =>
            policy.WithOrigins("http://localhost:4173")
                .WithMethods("GET")
                .WithHeaders("X-Lab-Cors-Probe")
                .AllowCredentials());
    });
}

var connectionString = builder.Configuration.GetConnectionString("SecureLab")
    ?? throw new InvalidOperationException(
        "Connection string 'SecureLab' не налаштовано.");

builder.Services.AddDbContext<SecureLabDbContext>(options =>
    options.UseNpgsql(connectionString));
builder.Services.AddMemoryCache();
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<LoginAttemptLimiter>();
builder.Services.AddScoped<IncidentQueries>();
builder.Services.AddSingleton<IncidentAccessRules>();
builder.Services.Configure<RouteHandlerOptions>(options => options.ThrowOnBadRequest = false);

builder.AddLab03Identity();

var app = builder.Build();

var resetRequested = args.Contains("--reset-database", StringComparer.Ordinal);
await DatabaseBootstrap.InitializeAsync(app.Services, app.Configuration, app.Environment, resetRequested);

if (resetRequested)
{
    return;
}

app.UseExceptionHandler();
app.UseStatusCodePages();

app.Use(async (context, next) =>
{
    context.Response.Headers.XContentTypeOptions = "nosniff";
    context.Response.Headers.Append("Referrer-Policy", "no-referrer");
    await next(context);
});

app.UseRouting();

if (app.Environment.IsDevelopment())
{
    app.UseCors("Lab05BrowserProbe");
}

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference();
}

app.UseAuthentication();
app.UseAuthorization();

app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/health", async (SecureLabDbContext dbContext, CancellationToken cancellationToken) =>
    await dbContext.Database.CanConnectAsync(cancellationToken)
        ? Results.Ok(new { status = "ready" })
        : Results.Problem(
            title: "База даних недоступна",
            statusCode: StatusCodes.Status503ServiceUnavailable))
    .WithName("GetHealth")
    .Produces(StatusCodes.Status200OK)
    .ProducesProblem(StatusCodes.Status503ServiceUnavailable);

app.MapIncidentEndpoints();
app.MapLab03Identity();
app.MapLab02Endpoints();
app.MapFallbackToFile("index.html");

app.Run();

public partial class Program;
