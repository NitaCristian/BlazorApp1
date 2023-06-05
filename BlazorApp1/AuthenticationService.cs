using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

public class AuthenticationService
{
    public event Action<ClaimsPrincipal>? UserChanged;
    private ClaimsPrincipal? currentUser;
    private readonly ProtectedLocalStorage localStorage;

    public AuthenticationService(ProtectedLocalStorage localStorage)
    {
        this.localStorage = localStorage;
    }

    public ClaimsPrincipal CurrentUser
    {
        get { return currentUser ?? new(); }
        set
        {
            currentUser = value;

            if (UserChanged is not null)
            {
                UserChanged(currentUser);
            }
        }
    }

    public async Task SignInUser(string token)
    {
        await localStorage.SetAsync("jwtToken", token);

        var claims = ParseJwtToken(token);
        var identity = new ClaimsIdentity(claims, "jwtAuthType");
        CurrentUser = new ClaimsPrincipal(identity);
    }

    public async Task SignOutUser()
    {
        await localStorage.DeleteAsync("jwtToken");
        CurrentUser = new ClaimsPrincipal();
    }

    private IEnumerable<Claim> ParseJwtToken(string token)
    {
        var handler = new JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(token);
        return jwtToken.Claims;
    }
}
