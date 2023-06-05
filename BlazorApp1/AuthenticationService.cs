using BlazorApp1;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

public class AuthenticationService
{
    private readonly AuthenticationStateProvider authenticationStateProvider;
    private readonly ProtectedLocalStorage localStorage;
    private readonly IConfiguration _configuration;

    public AuthenticationService(AuthenticationStateProvider authenticationStateProvider,
                                 ProtectedLocalStorage localStorage,
                                 IConfiguration configuration)
    {
        this.authenticationStateProvider = authenticationStateProvider;
        this.localStorage = localStorage;
        _configuration = configuration;
    }

    public async Task<bool> Login(UserDto model)
    {
        if (model.Username != "admin" || model.Password != "password")
            return false;

        var token = GenerateJwtToken(model.Username);
        await localStorage.SetAsync("jwtToken", token);
        ((CustomAuthenticationStateProvider)authenticationStateProvider).NotifyUserAuthentication(token);

        return true;
    }

    public async Task SignOutUser()
    {
        await localStorage.DeleteAsync("jwtToken");
        ((CustomAuthenticationStateProvider)authenticationStateProvider).NotifyUserLogout();
    }

    private string GenerateJwtToken(string username)
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.Name, username),
            new Claim(ClaimTypes.Role, "Admin"),
            new Claim(ClaimTypes.NameIdentifier, "id")
        };

        var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(
            _configuration.GetSection("AppSettings:Token").Value));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);
        var token = new JwtSecurityToken(
            claims: claims,
            notBefore: DateTime.UtcNow,
            expires: DateTime.UtcNow.AddSeconds(10),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
    {
        using (var hmac = new HMACSHA512())
        {
            passwordSalt = hmac.Key;
            passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
        }
    }

    private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
    {
        using (var hmac = new HMACSHA512(passwordSalt))
        {
            var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            return computedHash.SequenceEqual(passwordHash);
        }
    }
}
