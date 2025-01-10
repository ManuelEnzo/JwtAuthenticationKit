using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;

namespace JwtAuthenticationKit.Services
{
    public interface IJwtService
    {
        string GenerateToken(string userId, string role);
        ClaimsPrincipal ValidateToken(string token);
        string GenerateRefreshToken();
    }

    public class JwtService : IJwtService
    {
        private readonly JwtOptions _options;

        public JwtService(JwtOptions options)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
        }

        /// <summary>
        /// Generate a JWT token for the given user id and role
        /// </summary>
        /// <param name="userId">User id</param>
        /// <param name="role">Role</param>
        /// <returns></returns>
        public string GenerateToken(string userId, string role)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_options.SecretKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, userId),
                new Claim(ClaimTypes.Role, role)
            };

            var token = new JwtSecurityToken(
                issuer: _options.Issuer,
                audience: _options.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(_options.ExpirationMinutes),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        /// <summary>
        /// Validate the given token and return the principal 
        /// </summary>
        /// <param name="token">Token</param>
        /// <returns></returns>
        public ClaimsPrincipal ValidateToken(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_options.SecretKey);

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = _options.Issuer,
                ValidAudience = _options.Audience,
                IssuerSigningKey = new SymmetricSecurityKey(key)
            };

            return tokenHandler.ValidateToken(token, validationParameters, out _);
        }

        /// <summary>
        /// Generate a refresh token that can be used to get a new access token
        /// </summary>
        /// <returns>Refresh token</returns>
        public string GenerateRefreshToken()
        {
            // Create a random string for the refresh token using RandomNumberGenerator (recommended over RNGCryptoServiceProvider)
            var randomNumber = new byte[32];
            using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
            }
            return Convert.ToBase64String(randomNumber);
        }

       

    }
}
