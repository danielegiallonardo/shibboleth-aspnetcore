﻿using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Shibboleth.AspNetCore.Authentication.Models;

namespace Shibboleth.AspNetCore.Authentication.Events
{
    public sealed class SecurityTokenCreatingContext : RemoteAuthenticationContext<ShibbolethOptions>
    {
        /// <summary>
        /// Creates a <see cref="SecurityTokenValidatedContext"/>
        /// </summary>
        public SecurityTokenCreatingContext(HttpContext context, AuthenticationScheme scheme, ShibbolethOptions options, AuthenticationProperties properties)
            : base(context, scheme, options, properties) { }

        public SecurityTokenCreatingOptions TokenOptions { get; internal set; }
        /// <summary>
        /// Gets the saml authn request identifier.
        /// </summary>
        /// <value>
        /// The saml authn request identifier.
        /// </value>
        public string SamlAuthnRequestId { get; internal set; }
    }
}
