namespace JwtAuthenticationKit
{
    public class JwtOptions
    {
        public string Issuer { get; set; } = string.Empty;
        public string Audience { get; set; } = string.Empty;
        public string SecretKey { get; set; } = string.Empty;
        public int ExpirationMinutes { get; set; } = 60;

        public JwtOptions WithJwtKey(string key)
        {
            SecretKey = key;
            return this;
        }

        public JwtOptions WithIssuer(string issuer)
        {
            Issuer = issuer;
            return this;
        }

        public JwtOptions WithAudience(string audience)
        {
            Audience = audience;
            return this;
        }

        public JwtOptions WithExpiryMinutes(int minutes)
        {
            ExpirationMinutes = minutes;
            return this;
        }
    }
}
