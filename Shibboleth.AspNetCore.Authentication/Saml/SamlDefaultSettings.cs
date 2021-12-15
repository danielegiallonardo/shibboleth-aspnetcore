﻿using Shibboleth.AspNetCore.Authentication.Resources;
using System;
using System.Globalization;

namespace Shibboleth.AspNetCore.Authentication.Saml
{
    internal class SamlDefaultSettings
    {
        /// <summary>
        /// The date time format
        /// </summary>
        public const string DateTimeFormat = "yyyy-MM-ddTHH:mm:ss.fffZ";
        public const string DateTimeShortFormat = "yyyy-MM-ddTHH:mm:ssZ";

        public static DateTime ParseExact(string s, string fieldName)
        {
            DateTime result = default;
            if (!(DateTime.TryParseExact(s, DateTimeFormat, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out result)
                || DateTime.TryParseExact(s, DateTimeShortFormat, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out result)))
            {
                throw new System.Exception(string.Format(ErrorLocalization.ParameterNotValid, fieldName));
            };
            return result;
        }

        /// <summary>
        /// The now delta
        /// </summary>
        public const double NowDelta = 0;

        /// <summary>
        /// The AssertionConsumerServiceIndex
        /// </summary>
        public const ushort AssertionConsumerServiceIndex = 0;

        /// <summary>
        /// The AssertionConsumerServiceIndex
        /// </summary>
        public const ushort AttributeConsumingServiceIndex = 1;
    }
}
