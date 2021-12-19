using IdentityServer4;
using IdentityServer4.Models;
using Shibboleth.AspNetCore.Authentication.Models;
using System.Collections.Generic;

namespace Shibboleth.AspNetCore.IdentityServerSample.IdentityServer
{
    public class ShibbolethIdentityResource : IdentityResource
    {
        public ShibbolethIdentityResource()
        {
            base.Name = "Shibboleth";
            base.DisplayName = "Shibboleth claims";
            base.Description = "Information from Shibboleth claims";
            base.Emphasize = true;
            base.UserClaims = new List<string>()
            {
                ShibbolethClaimTypes.FiscalNumber.Value,
                ShibbolethClaimTypes.Mail.Value,
                ShibbolethClaimTypes.FirstName.Value,
                ShibbolethClaimTypes.Surname.Value,
            };
        }
    }

    public static class Config
    {
        public static IEnumerable<IdentityResource> IdentityResources =>
            new List<IdentityResource>
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
                new ShibbolethIdentityResource()
            };

        public static IEnumerable<Client> Clients =>
            new List<Client>
            {
                // interactive ASP.NET Core MVC client
                new Client
                {
                    ClientId = "mvc",
                    ClientSecrets = { new Secret("secret".Sha256()) },
                    AlwaysIncludeUserClaimsInIdToken = true,
                    AllowedGrantTypes = GrantTypes.Code,
                    
                    // where to redirect to after login
                    RedirectUris = { "https://localhost:5002/signin-oidc" },

                    // where to redirect to after logout
                    PostLogoutRedirectUris = { "https://localhost:5002/signout-callback-oidc" },

                    AllowedScopes = new List<string>
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        "Shibboleth"
                    }
                }
            };
    }
}