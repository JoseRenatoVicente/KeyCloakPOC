using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using KeyCloakPOC.Configurations;

var builder = WebApplication.CreateBuilder(args);
var configuration = builder.Configuration;

builder.Services.AddControllers();
builder.Services.AddSwaggerConfiguration();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.RequireHttpsMetadata = false;
        options.Authority = configuration["Jwt:Authority"];
        options.Audience = configuration["Jwt:Audience"];
        options.IncludeErrorDetails = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = false,
            ValidateIssuer = true,
            ValidIssuer = configuration["Jwt:Authority"],
            ValidateLifetime = true,
            RequireExpirationTime = true
        };
        options.Events = new JwtBearerEvents
        {
            OnTokenValidated = context =>
            {
                MapKeyCloakRolesToRoleClaims(context);
                return Task.CompletedTask;
            }
        };
    });

static void MapKeyCloakRolesToRoleClaims(TokenValidatedContext context)
{
    var clientRoles = context.Principal!.Claims.Where(w => w.Type == "user_realm_roles");

    if (context.Principal.Identity is not ClaimsIdentity claimsIdentity)
        return;

    foreach (var clientRole in clientRoles)
        claimsIdentity.AddClaim(new Claim(ClaimTypes.Role, clientRole.ToString()));
}

var app = builder.Build();

app.UseSwaggerSetup();
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.Run();