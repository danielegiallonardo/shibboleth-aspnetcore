using System.Collections.Generic;

namespace Shibboleth.AspNetCore.Authentication.Models
{
    public sealed class ShibbolethClaimTypes
    {
        private static Dictionary<string, ShibbolethClaimTypes> _types = new Dictionary<string, ShibbolethClaimTypes>() {
            { nameof(FirstName), new ShibbolethClaimTypes(nameof(FirstName)) },
            { nameof(Surname), new ShibbolethClaimTypes(nameof(Surname)) },
            { nameof(FiscalNumber), new ShibbolethClaimTypes(nameof(FiscalNumber)) },
            { nameof(Mail), new ShibbolethClaimTypes(nameof(Mail)) },
        };

        private ShibbolethClaimTypes(string value)
        {
            Value = value;
        }

        public string Value { get; private set; }

        public static ShibbolethClaimTypes FirstName { get { return _types[nameof(FirstName)]; } }
        public static ShibbolethClaimTypes Surname { get { return _types[nameof(Surname)]; } }
        public static ShibbolethClaimTypes FiscalNumber { get { return _types[nameof(FiscalNumber)]; } }
        public static ShibbolethClaimTypes Mail { get { return _types[nameof(Mail)]; } }
    }
}
