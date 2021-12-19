namespace Shibboleth.AspNetCore.Authentication.Models
{
    /// <summary>
    /// Default values related to Shibboleth authentication handler
    /// </summary>
    public sealed class ShibbolethDefaults
    {
        /// <summary>
        /// The default authentication type used when registering the ShibbolethHandler.
        /// </summary>
        public const string AuthenticationScheme = "Shibboleth";

        /// <summary>
        /// The default display name used when registering the ShibbolethHandler.
        /// </summary>
        public const string DisplayName = "Shibboleth";

        /// <summary>
        /// Constant used to identify userstate inside AuthenticationProperties that have been serialized in the 'wctx' parameter.
        /// </summary>
        public static readonly string UserstatePropertiesKey = "Shibboleth.Userstate";

        /// <summary>
        /// The cookie name
        /// </summary>
        public static readonly string CookieName = "Shibboleth.Properties";
    }
}
