using JwtAuthenticationKit;
using JwtAuthenticationKit.Services;
using Microsoft.AspNetCore.Authorization;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    // Aggiungi il supporto per l'inserimento del Bearer token in Swagger
    options.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
    {
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Description = "Please enter a valid token",
        Name = "Authorization",
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.ApiKey,
        BearerFormat = "JWT",
        Scheme = "Bearer"
    });

    options.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
    {
        {
            new Microsoft.OpenApi.Models.OpenApiSecurityScheme
            {
                Reference = new Microsoft.OpenApi.Models.OpenApiReference
                {
                    Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] {}
        }
    });
});

builder.Services.AddAuthorization();

// Configura JWT Authentication
builder.Services.AddJwtAuthentication(options =>
{
    options.Issuer = "MyApp";
    options.Audience = "MyAppUsers";
    options.SecretKey = "SuperSecretKey123!SuperSecretKey123!SuperSecretKey123!";
    options.ExpirationMinutes = 120;
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(options =>
    {
        // Aggiungi il supporto per inserire il Bearer token in Swagger UI
        options.OAuthClientId("swagger-client");
        options.OAuthAppName("Swagger UI");
    });
}

app.UseHttpsRedirection();
app.UseAuthentication();  // Assicurati che venga chiamato prima di UseAuthorization
app.UseAuthorization();

// Endpoint per il login che restituisce il token JWT e il refresh token
app.MapPost("/login", (LoginModel model, IJwtServices jwtService) =>
{
    if (model.Username == "user" && model.Password == "password")
    {
        var token = jwtService.GenerateToken(model.Username, "UserRole");
        var refreshToken = jwtService.GenerateRefreshToken();
        return Results.Ok(new { Token = token, RefreshToken = refreshToken });
    }
    return Results.Unauthorized();
});

// Endpoint per il refresh del token
app.MapPost("/refresh-token", (string refreshToken, IJwtServices jwtService) =>
{
    try
    {
        // Valida il refresh token
        var principal = jwtService.ValidateRefreshToken(refreshToken);

        // Genera un nuovo access token (è possibile anche rigenerare un refresh token)
        var newToken = jwtService.GenerateToken(principal.Identity.Name, "UserRole");
        var newRefreshToken = jwtService.GenerateRefreshToken();

        return Results.Ok(new { Token = newToken, RefreshToken = newRefreshToken });
    }
    catch (Exception)
    {
        return Results.Unauthorized();
    }
});


// Endpoint protetto che richiede un token JWT valido
app.MapGet("/secure-data", [Authorize] () =>
{
    return Results.Ok("This is a secured data!");
});

app.Run();

// Modello per il login
public class LoginModel
{
    public string Username { get; set; }
    public string Password { get; set; }
}
