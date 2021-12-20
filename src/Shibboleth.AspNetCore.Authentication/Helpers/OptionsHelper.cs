﻿using Shibboleth.AspNetCore.Authentication.Models;
using Microsoft.Extensions.Configuration;
using System.Security.Cryptography.X509Certificates;

namespace Shibboleth.AspNetCore.Authentication.Helpers
{
    internal class OptionsHelper
    {
        internal static ShibbolethConfiguration CreateFromConfiguration(IConfiguration configuration)
        {
            var section = configuration.GetSection("Shibboleth");
            var options = new ShibbolethConfiguration();

            var identityProviderSection = section.GetSection("Provider");
            if (identityProviderSection != null)
            {
                options.IdentityProvider = new IdentityProvider()
                {
                    Method = identityProviderSection.GetValue<RequestMethod>("Method"),
                    Name = identityProviderSection.GetValue<string>("Name"),
                    OrganizationDisplayName = identityProviderSection.GetValue<string>("OrganizationDisplayName"),
                    OrganizationLogoUrl = identityProviderSection.GetValue<string>("OrganizationLogoUrl"),
                    OrganizationName = identityProviderSection.GetValue<string>("OrganizationName"),
                    OrganizationUrl = identityProviderSection.GetValue<string>("OrganizationUrl"),
                    OrganizationUrlMetadata = identityProviderSection.GetValue<string>("OrganizationUrlMetadata"),
                    SingleSignOnServiceUrl = identityProviderSection.GetValue<string>("SingleSignOnServiceUrl"),
                    SingleSignOutServiceUrl = identityProviderSection.GetValue<string>("SingleSignOutServiceUrl"),
                    SecurityLevel = identityProviderSection.GetValue<int?>("SecurityLevel") ?? 3,
                };
            }

            options.AllowUnsolicitedLogins = section.GetValue<bool?>("AllowUnsolicitedLogins") ?? false;
            options.AssertionConsumerServiceIndex = section.GetValue<ushort?>("AssertionConsumerServiceIndex") ?? 0;
            options.AttributeConsumingServiceIndex = section.GetValue<ushort?>("AttributeConsumingServiceIndex") ?? 0;
            options.CallbackPath = section.GetValue<string>("CallbackPath");
            options.EntityId = section.GetValue<string>("EntityId");
            options.RemoteSignOutPath = section.GetValue<string>("RemoteSignOutPath");
            options.SignOutScheme = section.GetValue<string>("SignOutScheme");
            options.UseTokenLifetime = section.GetValue<bool?>("UseTokenLifetime") ?? false;
            options.SkipUnrecognizedRequests = section.GetValue<bool?>("SkipUnrecognizedRequests") ?? true;
            options.CacheIdpMetadata = section.GetValue<bool?>("CacheIdpMetadata") ?? false;
            options.SecurityLevel = section.GetValue<int?>("SecurityLevel") ?? 2;
            var certificateSection = section.GetSection("Certificate");
            if (certificateSection != null)
            {
                var certificateSource = certificateSection.GetValue<string>("Source");
                if (certificateSource == "Store")
                {
                    var storeConfiguration = certificateSection.GetSection("Store");
                    var location = storeConfiguration.GetValue<StoreLocation>("Location");
                    var name = storeConfiguration.GetValue<StoreName>("Name");
                    var findType = storeConfiguration.GetValue<X509FindType>("FindType");
                    var findValue = storeConfiguration.GetValue<string>("FindValue");
                    var validOnly = storeConfiguration.GetValue<bool>("validOnly");
                    options.Certificate = X509Helpers.GetCertificateFromStore(
                                        location,
                                        name,
                                        findType,
                                        findValue,
                                        validOnly);
                }
                else if (certificateSource == "File")
                {
                    var storeConfiguration = certificateSection.GetSection("File");
                    var path = storeConfiguration.GetValue<string>("Path");
                    var password = storeConfiguration.GetValue<string>("Password");
                    options.Certificate = X509Helpers.GetCertificateFromFile(path, password);
                }
                else if (certificateSource == "Raw")
                {
                    var storeConfiguration = certificateSection.GetSection("Raw");
                    var certificate = storeConfiguration.GetValue<string>("Certificate");
                    var key = storeConfiguration.GetValue<string>("Password");
                    options.Certificate = X509Helpers.GetCertificateFromStrings(certificate, key);
                }
            }
            return options;
        }

        internal static void LoadFromConfiguration(ShibbolethConfiguration options, IConfiguration configuration)
        {
            var createdOptions = CreateFromConfiguration(configuration);
            options.IdentityProvider = createdOptions.IdentityProvider;
            options.AllowUnsolicitedLogins = createdOptions.AllowUnsolicitedLogins;
            options.AssertionConsumerServiceIndex = createdOptions.AssertionConsumerServiceIndex;
            options.AttributeConsumingServiceIndex = createdOptions.AttributeConsumingServiceIndex;
            options.CallbackPath = createdOptions.CallbackPath;
            options.Certificate = createdOptions.Certificate;
            options.EntityId = createdOptions.EntityId;
            options.RemoteSignOutPath = createdOptions.RemoteSignOutPath;
            options.SignOutScheme = createdOptions.SignOutScheme;
            options.SkipUnrecognizedRequests = createdOptions.SkipUnrecognizedRequests;
            options.UseTokenLifetime = createdOptions.UseTokenLifetime;
        }
    }
}
