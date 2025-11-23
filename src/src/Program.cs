using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

var secret = "dev_secret_change_me_very_long_secret_key_123";
var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = key,
            ClockSkew = TimeSpan.Zero
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy =>
        policy.RequireClaim(ClaimTypes.Role, "admin"));
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

var users = new[]
{
    new { Id = 1, Email = "admin@example.com", Password = "admin123", Role = "admin" },
    new { Id = 2, Email = "user@example.com", Password = "user123", Role = "user" }
};

app.MapPost("/login", (LoginModel model) =>
{
    var user = users.FirstOrDefault(x => x.Email == model.Email && x.Password == model.Password);
    if (user is null) return Results.Unauthorized();

    var claims = new[]
    {
        new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
        new Claim(JwtRegisteredClaimNames.Email, user.Email),
        new Claim(ClaimTypes.Role, user.Role)
    };

    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(claims),
        Expires = DateTime.UtcNow.AddMinutes(15),
        SigningCredentials = creds
    };

    var tokenHandler = new JwtSecurityTokenHandler();
    var token = tokenHandler.CreateToken(tokenDescriptor);

    return Results.Ok(new
    {
        access_token = tokenHandler.WriteToken(token),
        token_type = "Bearer",
        expires_in = 900
    });
});

app.MapGet("/profile", (ClaimsPrincipal user) =>
{
    var id = user.FindFirstValue(JwtRegisteredClaimNames.Sub);
    var role = user.FindFirstValue(ClaimTypes.Role);
    return Results.Ok(new { user_id = id, role = role, message = "Secure data access" });
})
.RequireAuthorization();

app.MapDelete("/users/{id}", (int id) =>
{
    return Results.Ok(new { message = $"User {id} deleted (demo)" });
})
.RequireAuthorization("AdminOnly");

app.Run();

record LoginModel(string Email, string Password);