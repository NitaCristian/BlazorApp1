using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

public class CustomAuthenticationStateProvider : AuthenticationStateProvider
{
    private readonly ProtectedLocalStorage localStorage;

    public CustomAuthenticationStateProvider(ProtectedLocalStorage localStorage)
    {
        this.localStorage = localStorage;
    }

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        var token = await localStorage.GetAsync<string>("jwtToken");

        var anonymous = new AuthenticationState(new ClaimsPrincipal());

        if (string.IsNullOrWhiteSpace(token.Value))
            return anonymous;

        var jwtToken = new JwtSecurityTokenHandler().ReadJwtToken(token.Value);

        if (jwtToken.ValidTo < DateTime.UtcNow)
        {
            await localStorage.DeleteAsync("jwtToken");
            return anonymous;
        }

        return new AuthenticationState(
            new ClaimsPrincipal(
                new ClaimsIdentity(jwtToken.Claims, "jwtAuthType")));
    }

    public void NotifyUserAuthentication(string token)
    {
        var authenticatedUser = new ClaimsPrincipal(
            new ClaimsIdentity(
                new JwtSecurityTokenHandler().ReadJwtToken(token).Claims, "jwtAuthType"));

        var authenticationState = Task.FromResult(new AuthenticationState(authenticatedUser));
        NotifyAuthenticationStateChanged(authenticationState);
    }

    public void NotifyUserLogout()
    {
        var authenticationState = Task.FromResult(new AuthenticationState(new ClaimsPrincipal()));
        NotifyAuthenticationStateChanged(authenticationState);
    }
}
