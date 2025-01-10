using JwtAuthenticationKit.DatabaseCtx;
using JwtAuthenticationKit.Model;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace TestJWT.DatabaseCxtex
{
    public class MyCustomJwtAuthDbContext : IdentityDbContext<UserBaseModel>
    {
        public MyCustomJwtAuthDbContext(DbContextOptions<MyCustomJwtAuthDbContext> options): base(options) { }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
        }
    }

   
}
