using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Shibboleth.AspNetCore.Authentication.Helpers;
using Shibboleth.AspNetCore.Authentication.Models;
using System;
using System.Security.Claims;

namespace Shibboleth.AspNetCore.Authentication
{
    public static class ShibbolethExtensions
    {
        /// <summary>
        /// Registers the <see cref="ShibbolethHandler"/> using the default authentication scheme, display name, and options.
        /// </summary>
        /// <param name="builder"></param>
        /// <returns></returns>
        public static AuthenticationBuilder AddShibboleth(this AuthenticationBuilder builder, IConfiguration configuration)
            => builder.AddShibboleth(ShibbolethDefaults.AuthenticationScheme, o => { o.LoadFromConfiguration(configuration); });

        /// <summary>
        /// Registers the <see cref="ShibbolethHandler"/> using the default authentication scheme, display name, and the given options configuration.
        /// </summary>
        /// <param name="builder"></param>
        /// <param name="configureOptions">A delegate that configures the <see cref="ShibbolethOptions"/>.</param>
        /// <returns></returns>
        public static AuthenticationBuilder AddShibboleth(this AuthenticationBuilder builder, Action<ShibbolethOptions> configureOptions)
            => builder.AddShibboleth(ShibbolethDefaults.AuthenticationScheme, configureOptions);

        /// <summary>
        /// Registers the <see cref="ShibbolethHandler"/> using the given authentication scheme, default display name, and the given options configuration.
        /// </summary>
        /// <param name="builder"></param>
        /// <param name="authenticationScheme"></param>
        /// <param name="configureOptions">A delegate that configures the <see cref="ShibbolethOptions"/>.</param>
        /// <returns></returns>
        public static AuthenticationBuilder AddShibboleth(this AuthenticationBuilder builder, string authenticationScheme, Action<ShibbolethOptions> configureOptions)
            => builder.AddShibboleth(authenticationScheme, ShibbolethDefaults.DisplayName, configureOptions);

        /// <summary>
        /// Registers the <see cref="ShibbolethHandler"/> using the given authentication scheme, display name, and options configuration.
        /// </summary>
        /// <param name="builder"></param>
        /// <param name="authenticationScheme"></param>
        /// <param name="displayName"></param>
        /// <param name="configureOptions">A delegate that configures the <see cref="ShibbolethOptions"/>.</param>
        /// <returns></returns>
        public static AuthenticationBuilder AddShibboleth(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<ShibbolethOptions> configureOptions)
        {
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<ShibbolethOptions>, ShibbolethPostConfigureOptions>());
            builder.Services.TryAdd(ServiceDescriptor.Singleton<IActionContextAccessor, ActionContextAccessor>());
            builder.Services.AddHttpClient(authenticationScheme);
            builder.Services.TryAddScoped(factory =>
            {
                var actionContext = factory.GetService<IActionContextAccessor>().ActionContext;
                var urlHelperFactory = factory.GetService<IUrlHelperFactory>();
                return urlHelperFactory.GetUrlHelper(actionContext);
            });
            builder.Services.AddOptions<ShibbolethOptions>().Configure(configureOptions);
            return builder.AddRemoteScheme<ShibbolethOptions, ShibbolethHandler>(authenticationScheme, displayName, configureOptions);
        }

        /// <summary>
        /// Finds the first value.
        /// </summary>
        /// <param name="principal">The principal.</param>
        /// <param name="claimType">Type of the claim.</param>
        /// <returns></returns>
        public static string FindFirstValue(this ClaimsPrincipal principal, ShibbolethClaimTypes claimType)
        {
            return principal.FindFirstValue(claimType.Value);
        }

        /// <summary>
        /// Finds the first.
        /// </summary>
        /// <param name="principal">The principal.</param>
        /// <param name="claimType">Type of the claim.</param>
        /// <returns></returns>
        public static Claim FindFirst(this ClaimsPrincipal principal, ShibbolethClaimTypes claimType)
        {
            return principal.FindFirst(claimType.Value);
        }
    }
}
