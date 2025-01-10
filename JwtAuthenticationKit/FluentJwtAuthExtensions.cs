using JwtAuthenticationKit.DatabaseCtx;
using JwtAuthenticationKit.Model;
using JwtAuthenticationKit.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
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
        /// <summary>
        /// Add the JWT authentication services
        /// </summary>
        /// <param name="services"></param>
        /// <param name="configureOptions"></param>
        /// <returns></returns>
        public static IServiceCollection AddJwtAuthentication(this IServiceCollection services, Action<JwtOptions> configureOptions)
        {
            var options = new JwtOptions();
            configureOptions(options);

            services.TryAddSingleton(options);
            services.AddScoped<IJwtService, JwtService>();
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


        /// <summary>
        /// Add the database context for the JWT authentication and register the authentication service
        /// </summary>
        /// <typeparam name="TContext"></typeparam>
        /// <typeparam name="TUser"></typeparam>
        /// <param name="services"></param>
        /// <param name="options"></param>
        /// <returns></returns>
        public static IServiceCollection AddJwtAuthDatabase<TContext, TUser>(this IServiceCollection services, Action<DbContextOptionsBuilder> options)
                where TContext : IdentityDbContext<TUser>
                where TUser : IdentityUser
        {
            services.AddDbContext<TContext>(options);

            // Configura Identity
            services.AddIdentity<TUser, IdentityRole>()
                .AddEntityFrameworkStores<TContext>()
                .AddDefaultTokenProviders();

            // Configura il servizio di autenticazione
            services.AddScoped<IAuthenticationService<TUser>, AuthenticationService<TUser, TContext>>();

            return services;
        }
    }
}
