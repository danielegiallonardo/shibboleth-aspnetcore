﻿using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Shibboleth.AspNetCore.Authentication.Models;
using Shibboleth.AspNetCore.Authentication.Saml;

namespace Shibboleth.AspNetCore.Authentication.Events
{
    public sealed class MessageReceivedContext : RemoteAuthenticationContext<ShibbolethOptions>
    {
        /// <summary>
        /// Creates a new context object.
        /// </summary>
        /// <param name="context"></param>
        /// <param name="scheme"></param>
        /// <param name="options"></param>
        /// <param name="properties"></param>
        public MessageReceivedContext(
            HttpContext context,
            AuthenticationScheme scheme,
            ShibbolethOptions options,
            AuthenticationProperties properties,
            ResponseType protocolMessage)
            : base(context, scheme, options, properties)
        {
            ProtocolMessage = protocolMessage;
        }

        /// <summary>
        /// The <see cref="Response"/> received on this request.
        /// </summary>
        public ResponseType ProtocolMessage { get; set; }
    }
}
