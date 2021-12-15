using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Shibboleth.AspNetCore.Authentication.Models;
using Shibboleth.AspNetCore.Authentication.Saml;

namespace Shibboleth.AspNetCore.Authentication.Events
{
    public sealed class RemoteSignOutContext : RemoteAuthenticationContext<ShibbolethOptions>
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="context"></param>
        /// <param name="scheme"></param>
        /// <param name="options"></param>
        /// <param name="message"></param>
        public RemoteSignOutContext(HttpContext context, AuthenticationScheme scheme, ShibbolethOptions options, LogoutResponseType message)
            : base(context, scheme, options, new AuthenticationProperties())
            => ProtocolMessage = message;

        /// <summary>
        /// The signout message.
        /// </summary>
        public LogoutResponseType ProtocolMessage { get; set; }
    }
}
