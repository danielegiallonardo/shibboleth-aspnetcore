using Shibboleth.AspNetCore.Authentication.Helpers;
using Shibboleth.AspNetCore.Authentication.Models;
using Shibboleth.AspNetCore.Authentication.Resources;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using System.Xml.Serialization;

namespace Shibboleth.AspNetCore.Authentication.Saml
{
    internal static class SamlHandler
    {
        private static readonly Dictionary<Type, XmlSerializer> serializers = new Dictionary<Type, XmlSerializer>
        {
            { typeof(AuthnRequestType), new XmlSerializer(typeof(AuthnRequestType)) },
            { typeof(ResponseType), new XmlSerializer(typeof(ResponseType)) },
            { typeof(LogoutRequestType), new XmlSerializer(typeof(LogoutRequestType)) },
            { typeof(LogoutResponseType), new XmlSerializer(typeof(LogoutResponseType)) },
        };

        /// <summary>
        /// Build a signed SAML authentication request.
        /// </summary>
        /// <param name="requestId"></param>
        /// <param name="destination"></param>
        /// <param name="consumerServiceURL"></param>
        /// <param name="securityLevel"></param>
        /// <param name="certificate"></param>
        /// <param name="identityProvider"></param>
        /// <returns>Returns a Base64 Encoded String of the SAML request</returns>
        public static AuthnRequestType GetAuthnRequest(string requestId,
            string entityId,
            ushort? assertionConsumerServiceIndex,
            ushort? attributeConsumingServiceIndex,
            X509Certificate2 certificate,
            IdentityProvider identityProvider)
        {

            BusinessValidation.Argument(requestId, string.Format(ErrorLocalization.ParameterCantNullOrEmpty, nameof(requestId)));
            BusinessValidation.Argument(certificate, string.Format(ErrorLocalization.ParameterCantNull, nameof(certificate)));
            BusinessValidation.Argument(identityProvider, string.Format(ErrorLocalization.ParameterCantNull, nameof(identityProvider)));
            BusinessValidation.ValidationCondition(() => string.IsNullOrWhiteSpace(identityProvider.SingleSignOnServiceUrl), ErrorLocalization.SingleSignOnUrlRequired);

            if (string.IsNullOrWhiteSpace(identityProvider.DateTimeFormat))
            {
                identityProvider.DateTimeFormat = SamlDefaultSettings.DateTimeFormat;
            }

            if (identityProvider.NowDelta == null)
            {
                identityProvider.NowDelta = SamlDefaultSettings.NowDelta;
            }

            string dateTimeFormat = identityProvider.DateTimeFormat;
            double nowDelta = identityProvider.NowDelta.Value;

            DateTimeOffset now = DateTimeOffset.UtcNow;

            return new AuthnRequestType
            {
                ID = "_" + requestId,
                Version = SamlConst.Version,
                IssueInstant = now.AddMinutes(nowDelta).ToString(dateTimeFormat),
                Destination = identityProvider.SingleSignOnServiceUrl,
                ForceAuthn = identityProvider.SecurityLevel > 1,
                ForceAuthnSpecified = identityProvider.SecurityLevel > 1,
                Issuer = new NameIDType
                {
                    Value = entityId.Trim(),
                    Format = SamlConst.IssuerFormat,
                    NameQualifier = entityId
                },
                AssertionConsumerServiceIndex = assertionConsumerServiceIndex ?? SamlDefaultSettings.AssertionConsumerServiceIndex,
                AssertionConsumerServiceIndexSpecified = true,
                AttributeConsumingServiceIndex = attributeConsumingServiceIndex ?? SamlDefaultSettings.AttributeConsumingServiceIndex,
                AttributeConsumingServiceIndexSpecified = true,
                NameIDPolicy = new NameIDPolicyType
                {
                    Format = SamlConst.NameIDPolicyFormat,
                    AllowCreate = false,
                    AllowCreateSpecified = false
                },
                Conditions = new ConditionsType
                {
                    NotBefore = now.AddMinutes(-10).ToString(dateTimeFormat),
                    NotBeforeSpecified = true,
                    NotOnOrAfter = now.AddMinutes(10).ToString(dateTimeFormat),
                    NotOnOrAfterSpecified = true
                },
            };
        }

        /// <summary>
        /// Signs the request.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="message">The message.</param>
        /// <param name="certificate">The certificate.</param>
        /// <param name="uuid">The UUID.</param>
        /// <returns></returns>
        public static string SignRequest<T>(T message, X509Certificate2 certificate, string uuid) where T : class
        {
            var serializedMessage = SerializeMessage(message);

            var doc = new XmlDocument();
            doc.LoadXml(serializedMessage);

            var signature = XmlHelpers.SignXMLDoc(doc, certificate, uuid, SamlConst.SignatureMethod, SamlConst.DigestMethod);
            doc.DocumentElement.InsertBefore(signature, doc.DocumentElement.ChildNodes[1]);

            return Convert.ToBase64String(
                Encoding.UTF8.GetBytes("<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + doc.OuterXml),
                Base64FormattingOptions.None);
        }

        /// <summary>
        /// Get the IdP Authn Response and extract metadata to the returned DTO class
        /// </summary>
        /// <param name="base64Response"></param>
        /// <returns>IdpSaml2Response</returns>
        public static ResponseType GetAuthnResponse(string base64Response)
        {
            string idpResponse = null;
            BusinessValidation.Argument(base64Response, string.Format(ErrorLocalization.ParameterCantNullOrEmpty, nameof(base64Response)));
            BusinessValidation.ValidationTry(() => idpResponse = Encoding.UTF8.GetString(Convert.FromBase64String(base64Response)), ErrorLocalization.SingleSignOnUrlRequired);
            ResponseType response = null;
            try
            {
                response = DeserializeMessage<ResponseType>(idpResponse);

                BusinessValidation.ValidationCondition(() => response == null, ErrorLocalization.ResponseNotValid);

                return response;
            }
            catch (Exception ex)
            {
                throw new Exception(ErrorLocalization.ResponseNotValid, ex);
            }
        }

        /// <summary>
        /// Validates the authn response.
        /// </summary>
        /// <param name="response">The response.</param>
        /// <param name="request">The request.</param>
        /// <param name="metadataIdp">The metadata idp.</param>
        /// <exception cref="Exception">
        /// </exception>
        public static void ValidateAuthnResponse(this ResponseType response, AuthnRequestType request, EntityDescriptor metadataIdp)
        {
            // Verify signature
            var xmlDoc = response.SerializeToXmlDoc();

            BusinessValidation.ValidationCondition(() => response.Status == null, ErrorLocalization.StatusNotValid);
            BusinessValidation.ValidationCondition(() => response.Status.StatusCode == null, ErrorLocalization.StatusCodeNotValid);

            //BusinessValidation.ValidationCondition(() => response.Signature == null, ErrorLocalization.ResponseSignatureNotFound);
            //BusinessValidation.ValidationCondition(() => response?.GetAssertion() == null, ErrorLocalization.ResponseAssertionNotFound);
            //BusinessValidation.ValidationCondition(() => response.GetAssertion()?.Signature == null, ErrorLocalization.AssertionSignatureNotFound);
            //BusinessValidation.ValidationCondition(() => response.GetAssertion().Signature.KeyInfo.GetX509Data().GetBase64X509Certificate() != response.Signature.KeyInfo.GetX509Data().GetBase64X509Certificate(), ErrorLocalization.AssertionSignatureDifferent);
            //var metadataXmlDoc = metadataIdp.SerializeToXmlDoc();
            //BusinessValidation.ValidationCondition(() => XmlHelpers.VerifySignature(xmlDoc, metadataXmlDoc), ErrorLocalization.InvalidSignature);

            //using var responseCertificate = new X509Certificate2(response.Signature.KeyInfo.GetX509Data().GetRawX509Certificate());
            //using var assertionCertificate = new X509Certificate2(response.GetAssertion()?.Signature.KeyInfo.GetX509Data().GetRawX509Certificate());
            //using var idpCertificate = new X509Certificate2(Convert.FromBase64String(metadataIdp.IDPSSODescriptor.KeyDescriptor.KeyInfo.X509Data.X509Certificate));

            //BusinessValidation.ValidationCondition(() => responseCertificate.Thumbprint != idpCertificate.Thumbprint, ErrorLocalization.ResponseSignatureNotValid);
            //BusinessValidation.ValidationCondition(() => assertionCertificate.Thumbprint != idpCertificate.Thumbprint, ErrorLocalization.AssertionSignatureNotValid);

            BusinessValidation.ValidationCondition(() => response.Version != SamlConst.Version, ErrorLocalization.VersionNotValid);
            BusinessValidation.ValidationNotNullNotWhitespace(response.ID, nameof(response.ID));

            BusinessValidation.ValidationNotNull(response.GetAssertion()?.GetAttributeStatement(), ErrorFields.Assertion);
            BusinessValidation.ValidationCondition(() => response.GetAssertion().GetAttributeStatement()?.GetAttributes()?.Count() == 0, ErrorLocalization.AttributeNotFound);
            BusinessValidation.ValidationCondition(() => response.GetAssertion().GetAttributeStatement()?.GetAttributes()?.Any(a => a.AttributeValue == null) ?? false, ErrorLocalization.AttributeNotFound);

            var listAttribute = new List<string>
            {
                SamlConst.fiscalNumber
            };

            listAttribute.Add(SamlConst.firstname);
            listAttribute.Add(SamlConst.surname);
            listAttribute.Add(SamlConst.mail);

            var attribute = response.GetAssertion().GetAttributeStatement().GetAttributes();
            var attributeNames = attribute.Where(x => !string.IsNullOrWhiteSpace(x.Name) && !x.Name.StartsWith("urn")).Select(x => x.Name).ToList();
            var attributeFriendlyName = attribute.Where(x => !string.IsNullOrWhiteSpace(x.FriendlyName)).Select(x => x.FriendlyName).ToList();
            BusinessValidation.ValidationCondition(() => attributeNames.Count() == 0 && attributeFriendlyName.Count() == 0, ErrorLocalization.AttributeRequiredNotFound);

            if (attributeNames.Count() > 0)
                BusinessValidation.ValidationCondition(() => !listAttribute.All(x => attributeNames.Contains(x)), ErrorLocalization.AttributeRequiredNotFound);
            if (attributeFriendlyName.Count() > 0)
                BusinessValidation.ValidationCondition(() => !listAttribute.All(x => attributeFriendlyName.Contains(x)), ErrorLocalization.AttributeRequiredNotFound);
        }

        /// <summary>
        /// Build a signed SAML logout request.
        /// </summary>
        /// <param name="requestId"></param>
        /// <param name="destination"></param>
        /// <param name="consumerServiceURL"></param>
        /// <param name="certificate"></param>
        /// <param name="identityProvider"></param>
        /// <param name="subjectNameId"></param>
        /// <param name="authnStatementSessionIndex"></param>
        /// <returns></returns>
        public static LogoutRequestType GetLogoutRequest(string requestId, string consumerServiceURL, X509Certificate2 certificate,
           IdentityProvider identityProvider, string subjectNameId, string authnStatementSessionIndex)
        {

            BusinessValidation.Argument(requestId, string.Format(ErrorLocalization.ParameterCantNullOrEmpty, nameof(requestId)));
            BusinessValidation.Argument(subjectNameId, string.Format(ErrorLocalization.ParameterCantNullOrEmpty, nameof(subjectNameId)));
            BusinessValidation.Argument(consumerServiceURL, string.Format(ErrorLocalization.ParameterCantNullOrEmpty, nameof(consumerServiceURL)));
            BusinessValidation.Argument(certificate, string.Format(ErrorLocalization.ParameterCantNull, nameof(certificate)));
            BusinessValidation.Argument(identityProvider, string.Format(ErrorLocalization.ParameterCantNull, nameof(identityProvider)));

            if (string.IsNullOrWhiteSpace(identityProvider.DateTimeFormat))
            {
                identityProvider.DateTimeFormat = SamlDefaultSettings.DateTimeFormat;
            }

            if (identityProvider.NowDelta == null)
            {
                identityProvider.NowDelta = SamlDefaultSettings.NowDelta;
            }

            if (string.IsNullOrWhiteSpace(identityProvider.SingleSignOutServiceUrl))
            {
                throw new ArgumentNullException("The LogoutServiceUrl of the identity provider is null or empty.");
            }

            string dateTimeFormat = identityProvider.DateTimeFormat;
            string singleLogoutServiceUrl = identityProvider.SingleSignOutServiceUrl;

            DateTime now = DateTime.UtcNow;

            return new LogoutRequestType
            {
                ID = "_" + requestId,
                Version = "2.0",
                IssueInstant = now.ToString(dateTimeFormat),
                Destination = singleLogoutServiceUrl,
                Issuer = new NameIDType
                {
                    Value = consumerServiceURL.Trim(),
                    Format = SamlConst.IssuerFormat,
                    NameQualifier = consumerServiceURL
                },
                Item = new NameIDType
                {
                    NameQualifier = consumerServiceURL,
                    Format = SamlConst.NameIDPolicyFormat,
                    Value = subjectNameId
                },
                NotOnOrAfterSpecified = true,
                NotOnOrAfter = now.AddMinutes(10),
                Reason = SamlConst.LogoutUserProtocol,
                SessionIndex = new string[] { authnStatementSessionIndex }
            };

        }

        /// <summary>
        /// Get the IdP Logout Response and extract metadata to the returned DTO class
        /// </summary>
        /// <param name="base64Response"></param>
        /// <returns></returns>
        public static LogoutResponseType GetLogoutResponse(string base64Response)
        {
            string logoutResponse;

            if (String.IsNullOrEmpty(base64Response))
            {
                throw new ArgumentNullException("The base64Response parameter can't be null or empty.");
            }

            try
            {
                logoutResponse = Encoding.UTF8.GetString(Convert.FromBase64String(base64Response));
            }
            catch (Exception ex)
            {
                throw new ArgumentException("Unable to converto base64 response to ascii string.", ex);
            }

            try
            {
                return DeserializeMessage<LogoutResponseType>(logoutResponse);
            }
            catch (Exception ex)
            {
                throw new Exception(ErrorLocalization.ResponseNotValid, ex);
            }
        }

        /// <summary>
        /// Check the validity of IdP logout response
        /// </summary>
        /// <param name="response"></param>
        /// <param name="request"></param>
        /// <returns>True if valid, false otherwise</returns>
        public static bool ValidateLogoutResponse(LogoutResponseType response, LogoutRequestType request)
        {
            return (response.InResponseTo == request.ID);
        }

        /// <summary>
        /// Serializes the message.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="message">The message.</param>
        /// <returns></returns>
        public static string SerializeMessage<T>(T message) where T : class
        {
            var serializer = serializers[typeof(T)];
            var ns = new XmlSerializerNamespaces();
            ns.Add(SamlConst.samlp, SamlConst.Saml2pProtocol);
            ns.Add(SamlConst.saml, SamlConst.Saml2Assertion);

            var settings = new XmlWriterSettings
            {
                OmitXmlDeclaration = true,
                Indent = false,
                Encoding = Encoding.UTF8
            };

            using var stringWriter = new StringWriter();
            using var responseWriter = XmlTextWriter.Create(stringWriter, settings);
            serializer.Serialize(responseWriter, message, ns);
            return stringWriter.ToString();
        }

        /// <summary>
        /// Deserializes the message.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="message">The message.</param>
        /// <returns></returns>
        public static T DeserializeMessage<T>(string message) where T : class
        {
            var serializer = serializers[typeof(T)];
            using var stringReader = new StringReader(message);
            return serializer.Deserialize(stringReader) as T;
        }

        private class ErrorFields
        {
            internal static readonly string Assertion = nameof(Assertion);
            internal static readonly string AttributeStatement = nameof(AttributeStatement);
            internal static readonly string ID = nameof(ID);
            internal static readonly string IssueInstant = nameof(IssueInstant);
            internal static readonly string Subject = nameof(Subject);
            internal static readonly string NameID = nameof(NameID);
            internal static readonly string Format = nameof(Format);
            internal static readonly string SubjectConfirmation = nameof(SubjectConfirmation);
            internal static readonly string Method = nameof(Method);
            internal static readonly string SubjectConfirmationData = nameof(SubjectConfirmationData);
            internal static readonly string InResponseTo = nameof(InResponseTo);
            internal static readonly string Issuer = nameof(Issuer);
            internal static readonly string NotOnOrAfter = nameof(NotOnOrAfter);
            internal static readonly string NotBefore = nameof(NotBefore);
            internal static readonly string AudienceRestriction = nameof(AudienceRestriction);
            internal static readonly string Audience = nameof(Audience);
            internal static readonly string AuthnStatement = nameof(AuthnStatement);
            internal static readonly string AuthnContext = nameof(AuthnContext);
            internal static readonly string AuthnContextClassRef = nameof(AuthnContextClassRef);
            internal static readonly string Version = nameof(Version);
        }
    }
}
