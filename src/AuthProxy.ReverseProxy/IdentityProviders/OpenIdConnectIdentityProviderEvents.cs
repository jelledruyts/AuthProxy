using System.Security.Claims;
using System.Text.Json;
using AuthProxy.ReverseProxy.Infrastructure;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace AuthProxy.ReverseProxy.IdentityProviders;

public class OpenIdConnectIdentityProviderEvents<TIdentityProvider> : OpenIdConnectEvents where TIdentityProvider : IdentityProvider
{
    public TIdentityProvider IdentityProvider { get; }
    public ClaimsTransformer ClaimsTransformer { get; }
    public IDictionary<string, string> AdditionalParameters { get; }
    public IDictionary<string, string> AdditionalParametersForLogout { get; }

    public OpenIdConnectIdentityProviderEvents(TIdentityProvider identityProvider, ClaimsTransformer claimsTransformer)
    {
        this.IdentityProvider = identityProvider;
        this.ClaimsTransformer = claimsTransformer;
        this.AdditionalParameters = this.IdentityProvider.Configuration.AdditionalParameters.ParseKeyValuePairs(false);
        this.AdditionalParametersForLogout = this.IdentityProvider.Configuration.AdditionalParametersForLogout.ParseKeyValuePairs(false);
    }

    public override Task RedirectToIdentityProvider(RedirectContext context)
    {
        // Pass through additional parameters if requested.
        context.ProtocolMessage.Parameters.Merge(this.AdditionalParameters);
        return Task.CompletedTask;
    }

    public override Task RedirectToIdentityProviderForSignOut(RedirectContext context)
    {
        // Pass through additional parameters if requested.
        context.ProtocolMessage.Parameters.Merge(this.AdditionalParametersForLogout);
        return Task.CompletedTask;
    }

    public async override Task TokenValidated(TokenValidatedContext context)
    {
        // Invoked when an IdToken has been validated and produced an AuthenticationTicket.
        context.Principal = await this.ClaimsTransformer.TransformPrincipalAsync(context.Principal);
    }

    public async override Task UserInformationReceived(UserInformationReceivedContext context)
    {
        // Invoked when the UserInfo endpoint has been called and returned a user object.
        // Collect the user info properties as claims, which are kept as reference in a UserInfo identity.
        // Transform the user object claims as well, and add them to the BackendApp identity.
        var userInfoClaims = new List<Claim>();
        CollectClaimsFromJsonElement(userInfoClaims, context.User.RootElement);
        var userInfoIdentity = new ClaimsIdentity(userInfoClaims, Constants.AuthenticationTypes.UserInfo);
        var identities = context.Principal?.Identities.ToList() ?? new List<ClaimsIdentity>();
        identities.Add(userInfoIdentity);
        context.Principal = await this.ClaimsTransformer.TransformIdentitiesAsync(identities);
    }

    private static void CollectClaimsFromJsonElement(IList<Claim> claims, JsonElement element, string? parentKey = null)
    {
        foreach (var property in element.EnumerateObject())
        {
            var claimType = parentKey == null ? property.Name : $"{parentKey}.{property.Name}";
            switch (property.Value.ValueKind)
            {
                case JsonValueKind.Object:
                    CollectClaimsFromJsonElement(claims, property.Value, claimType);
                    break;
                case JsonValueKind.Array:
                    foreach (var item in property.Value.EnumerateArray())
                    {
                        if (item.ValueKind == JsonValueKind.Object)
                        {
                            CollectClaimsFromJsonElement(claims, item, claimType);
                        }
                        else
                        {
                            claims.Add(new Claim(claimType, item.ToString()));
                        }
                    }
                    break;
                default:
                    claims.Add(new Claim(claimType, property.Value.ToString()));
                    break;
            }
        }
    }
}