﻿using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Shibboleth.AspNetCore.Authentication.Models;
using Shibboleth.AspNetCore.Authentication.Saml;
using System;

namespace Shibboleth.AspNetCore.Authentication.Events
{
    public sealed class AuthenticationFailedContext : RemoteAuthenticationContext<ShibbolethOptions>
    {
        /// <summary>
        /// Creates a new context object
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="scheme">The scheme.</param>
        /// <param name="options">The options.</param>
        /// <param name="message">The message.</param>
        /// <param name="exception">The exception.</param>
        public AuthenticationFailedContext(HttpContext context, AuthenticationScheme scheme, ShibbolethOptions options, ResponseType message, Exception exception)
            : base(context, scheme, options, new AuthenticationProperties())
        {
            ProtocolMessage = message;
            Exception = exception;
        }

        /// <summary>
        /// The <see cref="Response"/> from the request, if any.
        /// </summary>
        public ResponseType ProtocolMessage { get; set; }

        /// <summary>
        /// The <see cref="Exception"/> that triggered this event.
        /// </summary>
        public Exception Exception { get; set; }
    }
}
