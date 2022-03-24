using AuthProxy.Configuration;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace AuthProxy.Infrastructure;

public class OpenIdConnectHandler
{
    public OpenIdConnectHandler(IdentityProviderConfig identityProvider, OpenIdConnectOptions options, string loginCallbackPath)
    {
        // Set main options.
        options.ClaimActions.Clear(); // Don't change any incoming claims, let the claims transformer do that.
        options.Authority = identityProvider.Authority;
        if (identityProvider.Scopes != null)
        {
            foreach (var scope in identityProvider.Scopes)
            {
                options.Scope.Add(scope);
            }
        }
        // options.Scope.Add(OpenIdConnectScope.OfflineAccess); // TODO: Only if needed, request a refresh token as part of the authorization code flow.
        options.ClientId = identityProvider.ClientId;
        options.ClientSecret = identityProvider.ClientSecret;
        options.CallbackPath = loginCallbackPath; // Note that the callback path must be unique per identity provider.

        // Set token validation parameters.
        options.TokenValidationParameters.ValidAudiences = identityProvider.AllowedAudiences;

        // Handle events.
        options.Events = new OpenIdConnectHandlerEvents(identityProvider);
    }

    private class OpenIdConnectHandlerEvents : OpenIdConnectEvents
    {
        private readonly IdentityProviderConfig identityProvider;
        private readonly IDictionary<string, string> additionalParameters;
        private readonly IDictionary<string, string> additionalParametersForLogout;
        private readonly ClaimsTransformer claimsTransformer;

        public OpenIdConnectHandlerEvents(IdentityProviderConfig identityProvider)
        {
            this.identityProvider = identityProvider;
            this.claimsTransformer = new ClaimsTransformer(this.identityProvider);
            this.additionalParameters = this.identityProvider.AdditionalParameters.ParseKeyValuePairs(false);
            this.additionalParametersForLogout = this.identityProvider.AdditionalParametersForLogout.ParseKeyValuePairs(false);
        }

        public override Task RedirectToIdentityProvider(RedirectContext context)
        {
            // Pass through additional parameters if requested.
            context.ProtocolMessage.Parameters.Merge(this.additionalParameters);
            return Task.CompletedTask;
        }

        public override Task RedirectToIdentityProviderForSignOut(RedirectContext context)
        {
            // Pass through additional parameters if requested.
            context.ProtocolMessage.Parameters.Merge(this.additionalParametersForLogout);
            return Task.CompletedTask;
        }

        public override Task TokenResponseReceived(TokenResponseReceivedContext context)
        {
            // Invoked after "authorization code" is redeemed for tokens at the token endpoint.
            // var identity = context.Principal?.Identity as ClaimsIdentity;
            return Task.CompletedTask;
        }

        public async override Task TokenValidated(TokenValidatedContext context)
        {
            // Invoked when an IdToken has been validated and produced an AuthenticationTicket.
            context.Principal = await this.claimsTransformer.TransformAsync(context.Principal);
            //context.Properties.IsPersistent = true; // Optionally ensure the session cookie is persistent across browser sessions.
        }
    }
}