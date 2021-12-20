# AspNetCore Remote Authenticator for Shibboleth
This is a custom implementation of an AspNetCore RemoteAuthenticationHandler for Shibboleth.

The purpose of this project is to provide a simple and immediate tool to integrate, in a WebApp developed with AspNetCore MVC, the authentication services of Shibboleth, automating the login/logout flows, the management of the SAML protocol, the security and simplifying development activities.

# Getting started

The library is distributed in the form of a NuGet package, which can be installed via the command

`Install-Package Shibboleth.AspNetCore.Authentication`

At this point it is sufficient, inside the `Startup.cs`, to add the following lines:

```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddControllersWithViews();
    services
        .AddAuthentication(o => {
            o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            o.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            o.DefaultChallengeScheme = ShibbolethDefaults.AuthenticationScheme;
        })
        .AddShibboleth(Configuration, o => {
            o.LoadFromConfiguration(Configuration);
        })
        .AddCookie();
}
```

In this way, the middleware necessary for the management of login/logout requests/responses from/to the Shibboleth identityProvider are added. 
These middleware add to the webapp the `/signin-shibboleth` and `/signout-shibboleth` endpoints on which the library listens to interpret the Login and Logout responses respectively coming from the Shibboleth IdentityProvider. 
These endpoints, in their absolute URL, and therefore including the schema and hostname (for example `https://webapp.customdomain.it/signin-shibboleth` and `https://webapp.customdomain.it/signout-shibboleth`), must be specified in the `AssertionConsumerService` and` SingleLogoutService` tags of the SP metadata, respectively.

A complete example of AspNetCore MVC webapp that makes use of this library is present within this repository under the folder `samples/Shibboleth.AspNetCore.WebApp`. To use it, simply configure the `AssertionConsumerServiceIndex`,` AttributeConsumingServiceIndex`, `EntityId` and` Certificate` parameters in `appsettings.json` with those related to your test metadata, and launch the webapp.

# Configuration
It is possible to configure the library by reading the settings from Configuration, using the statements:

```csharp
o.LoadFromConfiguration(Configuration);
```

In particular, it is possible to add a 'Shibboleth' section to the configuration which has the following format

```json
  "Shibboleth": {
    "Provider": {
      "Name": "Shibboleth IdP",
      "OrganizationName": "Shibboleth IdP",
      "OrganizationDisplayName": "Shibboleth IdP",
      "OrganizationUrlMetadata": "<Url_To_Shibboleth_Metadata>",
      "OrganizationUrl": "<IdP_Organization_Url>",
      "OrganizationLogoUrl": "<IdP_Organization_Logo_Url>",
      "SingleSignOnServiceUrl": "<IdP_SSO_Url>",
      "SingleSignOutServiceUrl": "<IdP_SLO_Url>",
      "Method": "Post",
      "SecurityLevel": 2
    },
    "Certificate": {
      "Source": "Store/Raw/File/None",
      "Store": {
        "Location": "CurrentUser",
        "Name": "My",
        "FindType": "FindBySubjectName",
        "FindValue": "CertificateSubjectName",
        "validOnly": false
      },
      "File": {
        "Path": "xxx.pfx",
        "Password": "xxx"
      },
      "Raw": {
        "Certificate": "test",
        "Password": "test"
      }
    },
    "EntityId": "https://entityID",
    "AssertionConsumerServiceIndex": 0,
    "AttributeConsumingServiceIndex": 0
  }
```

The configuration of the SP certificate is done by specifying in the `Source` field one of the values `Store/File/Raw/None` (in the case of `None` a certificate will not be loaded during startup, but it will be necessary to provide one at runtime, through the use of `CustomShibbolethEvents`, which will be presented in more detail in the next section) and by filling in the section corresponding to the specified value. The sections not used (ie those corresponding to the other values) can be safely deleted from the configuration file, since they will not be read.

Alternatively, you can configure all of the above options programmatically, from the `AddShibboleth(options => ...)` method.
The callback endpoints for signin and signout activities are set by default to `/signin-shibboleth` and `/signout-shibboleth`, respectively, but if you need to change these settings, you can override them (either from configuration or from code) by resetting the options `CallbackPath` and` RemoteSignOutPath`.

# Extension points
It is possible to intercept the various execution phases of the RemoteAuthenticator, overriding the events displayed by the option Events, and possibly use the DependencyInjection to have the various services configured in the webapp available.
This is useful both in the inspection phase of requests and responses to/from the Shibboleth identity provider, and to customize, at runtime, some parameters for generating the SAML request (for example in case you want to implement multitenancy). Eg

```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddControllersWithViews();
    services
        .AddAuthentication(o => {
            o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            o.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            o.DefaultChallengeScheme = ShibbolethDefaults.AuthenticationScheme;
        })
        .AddShibboleth(Configuration, o => {
            o.Events.OnTokenCreating = async (s) => await s.HttpContext.RequestServices.GetRequiredService<CustomShibbolethEvents>().TokenCreating(s);
	    o.Events.OnAuthenticationSuccess = async (s) => await s.HttpContext.RequestServices.GetRequiredService<CustomShibbolethEvents>().AuthenticationSuccess(s);
            o.LoadFromConfiguration(Configuration);
        })
        .AddCookie();
    services.AddScoped<CustomShibbolethEvents>();
}

.....

public class CustomShibbolethEvents : ShibbolethEvents
{
    private readonly IMyService _myService;
    public CustomShibbolethEvents(IMyService myService)
    {
        _myService = myService;
    }

    public override Task TokenCreating(SecurityTokenCreatingContext context)
    {
        var customConfig = _myService.ReadYourCustomConfigurationFromWhereverYouWant();
        context.TokenOptions.EntityId = customConfig.EntityId;
        context.TokenOptions.AssertionConsumerServiceIndex = customConfig.AssertionConsumerServiceIndex;
        context.TokenOptions.AttributeConsumingServiceIndex = customConfig.AttributeConsumingServiceIndex;
        context.TokenOptions.Certificate = customConfig.Certificate;

        return base.TokenCreating(context);
    }
    
    public override Task AuthenticationSuccess(AuthenticationSuccessContext context)
    {
        var principal = context.Principal;
	
	      // Data recovery from Shibboleth from ClaimsPrincipal
        var name = principal.FindFirst(ShibbolethClaimTypes.Name);
        var familyName = principal.FindFirst(ShibbolethClaimTypes.FamilyName);
        var email = principal.FindFirst(ShibbolethClaimTypes.Email);
        var dateOfBirth = principal.FindFirst(ShibbolethClaimTypes.DateOfBirth);
	      // .....
        return base.AuthenticationSuccess(context);
    }
}
```

# Error Handling
The library can, at any stage (both in the Request creation stage and in the Response management stage), raise exceptions.
A typical scenario is the one in which the error codes foreseen by the protocol are received, in this case the library raises an exception containing a corresponding error message, which can be managed (for example for visualization) using the normal flow provided for AspNetCore. The following example uses AspNetCore's ExceptionHandling middleware.

```csharp
public void Configure(IApplicationBuilder app, IHostEnvironment env)
{
    ...
    app.UseExceptionHandler("/Home/Error");
    ...
}

.......

// HomeController
[AllowAnonymous]
public async Task<IActionResult> Error()
{
    var exceptionHandlerPathFeature =
        HttpContext.Features.Get<IExceptionHandlerPathFeature>();

    string errorMessage = string.Empty;

    if (exceptionHandlerPathFeature?.Error != null)
    {
        var messages = FromHierarchy(exceptionHandlerPathFeature?.Error, ex => ex.InnerException)
            .Select(ex => ex.Message)
            .ToList();
        errorMessage = String.Join(" ", messages);
    }

    return View(new ErrorViewModel
    {
        RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier,
        Message = errorMessage
    });
}

private IEnumerable<TSource> FromHierarchy<TSource>(TSource source,
            Func<TSource, TSource> nextItem,
            Func<TSource, bool> canContinue)
{
    for (var current = source; canContinue(current); current = nextItem(current))
    {
        yield return current;
    }
}

private IEnumerable<TSource> FromHierarchy<TSource>(TSource source,
    Func<TSource, TSource> nextItem)
    where TSource : class
{
    return FromHierarchy(source, nextItem, s => s != null);
}
```


# Samples
Inside the `samples` folder you can find some example webapp implementations that make use of the library:

- 1_SimpleSPWebApp: simple AspNetCore MVC webapp that uses Shibboleth as a login system
- 2_IdentityServer: implementation of an instance of IdentityServer4 (which acts as an OIDC proxy towards Shibboleth) which uses Shibboleth as an external login system, and an MVC webapp federated with the instance of IdentityServer4

These are examples of library integration only, they should not be used "as-is" in production environments.

# Authors
* [Daniele Giallonardo](https://github.com/danielegiallonardo) (maintainer)
