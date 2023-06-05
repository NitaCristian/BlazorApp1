using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

public class CustomAuthenticationStateProvider : AuthenticationStateProvider
{
    private readonly AuthenticationService authService;
    private readonly ProtectedLocalStorage localStorage;

    public CustomAuthenticationStateProvider(AuthenticationService authService, ProtectedLocalStorage localStorage)
    {
        this.authService = authService;
        this.localStorage = localStorage;
    }

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        var jwtToken = await localStorage.GetAsync<string>("jwtToken");

        if (!string.IsNullOrEmpty(jwtToken.Value))
        {
            var claims = ParseJwtToken(jwtToken.Value);
            var identity = new ClaimsIdentity(claims, "jwtAuthType");
            authService.CurrentUser = new ClaimsPrincipal(identity);
        }
        else
        {
            authService.CurrentUser = new ClaimsPrincipal();
        }

        return new AuthenticationState(authService.CurrentUser);
    }

    private IEnumerable<Claim> ParseJwtToken(string token)
    {
        var handler = new JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(token);
        return jwtToken.Claims;
    }
}
