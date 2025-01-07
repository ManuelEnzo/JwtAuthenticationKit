using JwtAuthenticationKit.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JwtAuthenticationKit
{
    public static class FluentJwtAuthExtensions
    {
        public static IServiceCollection AddJwtAuthentication(this IServiceCollection services, Action<JwtOptions> configureOptions)
        {
            var options = new JwtOptions();
            configureOptions(options);

            services.TryAddSingleton(options);
            services.AddScoped<IJwtServices, JwtService>();

            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                 .AddJwtBearer(config =>
                 {
                     config.TokenValidationParameters = new TokenValidationParameters
                     {
                         ValidateIssuer = true,
                         ValidateAudience = true,
                         ValidateLifetime = true,
                         ValidateIssuerSigningKey = true,
                         ValidIssuer = options.Issuer,
                         ValidAudience = options.Audience,
                         IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(options.SecretKey))
                     };
                 });

            return services;
        }
    }
}
