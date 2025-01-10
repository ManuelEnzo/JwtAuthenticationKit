using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JwtAuthenticationKit.Services
{
    public interface IAuthenticationService<T> where T : class
    {
        Task<T> LoginAsync(string username, string password);
        Task<IdentityResult> RegisterAsync(T user, string password);
        Task LogoutAsync();
        Task<bool> ConfirmEmailAsync(T user, string token);
        Task<string> GenerateEmailConfirmationTokenAsync(T user);
        Task<bool> ResetPasswordAsync(T user, string token, string newPassword);
        Task<string> GeneratePasswordResetTokenAsync(T user);
        Task<bool> AddToRoleAsync(T user, string role);
        Task<bool> RemoveFromRoleAsync(T user, string role);
    }

    public class AuthenticationService<T, TDbContext> : IAuthenticationService<T>
         where T : IdentityUser
         where TDbContext : IdentityDbContext<T>
    {
        private readonly TDbContext _identityDb;
        private readonly UserManager<T> _userManager;
        private readonly SignInManager<T> _signInManager;

        public AuthenticationService(TDbContext identityDb, UserManager<T> userManager, SignInManager<T> signInManager)
        {
            _identityDb = identityDb;
            _userManager = userManager;
            _signInManager = signInManager;
        }

        public async Task<T> LoginAsync(string username, string password)
        {
            var user = await _identityDb.Users.SingleOrDefaultAsync(u => u.UserName == username);
            if (user != null)
            {
                var result = await _signInManager.PasswordSignInAsync(user, password, false, false);
                if (result.Succeeded)
                {
                    return user;
                }
            }
            return null;
        }

        public async Task<IdentityResult> RegisterAsync(T user, string password)
        {
            var result = await _userManager.CreateAsync(user, password);
            return result;
        }

        public async Task LogoutAsync()
        {
            await _signInManager.SignOutAsync();
        }

        public async Task<bool> ConfirmEmailAsync(T user, string token)
        {
            var result = await _userManager.ConfirmEmailAsync(user, token);
            return result.Succeeded;
        }

        public async Task<string> GenerateEmailConfirmationTokenAsync(T user)
        {
            return await _userManager.GenerateEmailConfirmationTokenAsync(user);
        }

        public async Task<bool> ResetPasswordAsync(T user, string token, string newPassword)
        {
            var result = await _userManager.ResetPasswordAsync(user, token, newPassword);
            return result.Succeeded;
        }

        public async Task<string> GeneratePasswordResetTokenAsync(T user)
        {
            return await _userManager.GeneratePasswordResetTokenAsync(user);
        }

        public async Task<bool> AddToRoleAsync(T user, string role)
        {
            var result = await _userManager.AddToRoleAsync(user, role);
            return result.Succeeded;
        }

        public async Task<bool> RemoveFromRoleAsync(T user, string role)
        {
            var result = await _userManager.RemoveFromRoleAsync(user, role);
            return result.Succeeded;
        }
    }
}
