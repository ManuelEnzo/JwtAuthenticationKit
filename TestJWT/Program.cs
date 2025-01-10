using JwtAuthenticationKit;
using JwtAuthenticationKit.DatabaseCtx;
using JwtAuthenticationKit.Model;
using JwtAuthenticationKit.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using TestJWT.DatabaseCxtex;
using static System.Runtime.InteropServices.JavaScript.JSType;

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

// Configura il database per JWT Authentication e il servizio di autenticazione
builder.Services.AddJwtAuthDatabase<MyCustomJwtAuthDbContext, UserBaseModel>(options =>
{
    options.UseSqlServer("Server=NBMENZO\\SQL2019;Database=SPECIAL;Trusted_Connection=False;UID=sa;pwd=X$agilis;TrustServerCertificate=True;");
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
app.MapPost("/login", async (LoginModel model, MyCustomJwtAuthDbContext dbContext, IAuthenticationService<UserBaseModel> authService, IJwtService jwtService) =>
{
    var user = await authService.LoginAsync(model.Username, model.Password);

    if (user != null)
    {
        var token = jwtService.GenerateToken(user.UserName, "UserRole");
        var refreshToken = jwtService.GenerateRefreshToken();

        user.RefreshToken = refreshToken;
        user.RefreshTokenExpiryTime = DateTime.Now.AddMinutes(60);
        dbContext.Entry(user).State = EntityState.Modified;
        await dbContext.SaveChangesAsync();
        return Results.Ok(new { Token = token, RefreshToken = refreshToken });
    }
    return Results.Unauthorized();
});

// Endpoint per la registrazione
app.MapPost("/register", async (RegisterModel model, IAuthenticationService<UserBaseModel> authService) =>
{
    var user = new UserBaseModel { UserName = model.Username, Email = model.Email };
    var result = await authService.RegisterAsync(user, model.Password);

    if (result.Succeeded)
    {
        return Results.Ok("User registered successfully");
    }

    if (result.Errors != null)
    {

        return Results.BadRequest(Results.ValidationProblem(
            new Dictionary<string, string[]>
            {
            { "Messages",  result.Errors.Select(e => e.Description).ToArray()}
            }));
    }
    return Results.BadRequest("Errors");
});

app.MapPost("/refresh-token", async (string jwtToken, MyCustomJwtAuthDbContext dbContext, IJwtService jwtService) =>
{
    var principal = jwtService.ValidateToken(jwtToken);
    var username = principal.Identity.Name;

    var user = await dbContext.Users.SingleOrDefaultAsync(u => u.UserName == username);

    if (user == null || user.RefreshTokenExpiryTime <= DateTime.Now)
    {
        return Results.Unauthorized();
    }

    var newToken = jwtService.GenerateToken(user.UserName, "UserRole");
    var newRefreshToken = jwtService.GenerateRefreshToken();

    user.RefreshToken = newRefreshToken;
    user.RefreshTokenExpiryTime = DateTime.Now.AddMinutes(60);
    dbContext.Entry(user).State = EntityState.Modified;
    await dbContext.SaveChangesAsync();

    return Results.Ok(new { Token = newToken, RefreshToken = newRefreshToken });
});

// Endpoint protetto che richiede un token JWT valido
app.MapGet("/secure-data", [Authorize] () =>
{
    return Results.Ok("This is a secured data!");
});

app.Run();

public class LoginModel
{
    public string Username { get; set; }
    public string Password { get; set; }
}

public class RegisterModel
{
    public string Username { get; set; }
    public string Email { get; set; }
    public string Password { get; set; }
}