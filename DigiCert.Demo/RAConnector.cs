using DigiCert.Demo.CertificateManagement;
using DigiCert.Demo.Enrollment;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Services.AppAuthentication;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.Text;
using System.Threading.Tasks;

namespace DigiCert.Demo
{
    public static class RAConnector
    {
        public static async Task<byte[]> Get(string name, string csr, string policyOid, string webmaster, X509Certificate2 cert)

        {
            byte[] token = null;
            var client = new SecurityTokenServiceClient(BindingHelper.Binding(), new EndpointAddress("https://pki-ws.symauth.com/pki-ws/enrollmentService"));
            try
            {
                client.ClientCredentials.SetCredentials(cert);
                var requestToken = new RequestSecurityTokenType
                {
                    Item = new RequestVSSecurityTokenEnrollmentType()
                    {
                        preferredLanguage = "en-US",
                        certificateProfileID = policyOid,
                        clientTransactionID = "cert_" + DateTime.Now.ToString(),
                        tokenType = TokenType.httpdocsoasisopenorgwss200401oasis200401wssx509tokenprofile10PKCS7,
                        requestType = RequestTypeEnum.httpdocsoasisopenorgwssxwstrust200512Issue,
                        binarySecurityToken = new BinarySecurityTokenType[]
                        {
                            new BinarySecurityTokenType()
                            {
                                ValueType = "http://schemas.verisign.com/pkiservices/2009/07/PKCS10",
                                Value = csr
                            }
                        },
                        nameValuePair = new NameValueType[]
                        {
                            new NameValueType()
                            {
                                name = "seat_id",
                                value = name
                            },
                            new NameValueType()
                            {
                                name = "common_name",
                                value = name
                            },
                            new NameValueType()
                            {
                                name = "mail",
                                value = webmaster
                            }
                        },
                        version = "2.0"
                    }
                };
                var responseObject = await client.RequestSecurityTokenAsync(requestToken);
                token = Encoding.ASCII.GetBytes(((AttributedString)(responseObject?.RequestSecurityTokenResponse?.Item).requestedVSSecurityToken.Items[0])?.Value);
            }
            catch (Exception e)
            {
                throw e;
            }
            finally
            {
                await client.CloseAsync();
            }
            return token;
        }

        public static async Task<bool> Delete(List<string> serialNumbers, X509Certificate2 cert)
        {
            bool success = true;
            var successMessage = new StringBuilder();
            foreach (string serialNumber in serialNumbers)
            {
                if (string.IsNullOrWhiteSpace(serialNumber))
                    continue;
                var client = new certificateManagementOperationsClient(BindingHelper.Binding(), new EndpointAddress("https://pki-ws.symauth.com/pki-ws/certificateManagementService"));
                try
                {
                    client.ClientCredentials.SetCredentials(cert);

                    var response = await client.updateCertificateStatusAsync(new UpdateCertificateStatusRequestType()
                    {
                        clientTransactionID = DateTime.Now.ToString(),
                        version = "1.0",
                        revocationReason = RevokeReasonCodeEnum.Superseded,
                        operationType = OperationTypeEnum.Revoke,
                        ItemElementName = ItemChoiceType.certificateSerialNumber,
                        Item = serialNumber,
                        revocationReasonSpecified = true
                    });
                    if (response != null && response.updateCertificateStatusResponse1.successCode < 0)
                        success = false;
                }
                catch (Exception e)
                {
                    throw e;
                }
                finally
                {
                    await client.CloseAsync();
                }
            }
            return success;
        }

        public static async Task<bool> Delete(string seatName, X509Certificate2 cert)
        {
            var successMessage = new StringBuilder();

            var client = new certificateManagementOperationsClient(BindingHelper.Binding(), new EndpointAddress("https://pki-ws.symauth.com/pki-ws/certificateManagementService"));
            try
            {
                client.ClientCredentials.SetCredentials(cert);

                var response = await client.updateCertificateStatusAsync(new UpdateCertificateStatusRequestType()
                {
                    clientTransactionID = DateTime.Now.ToString(),
                    version = "1.0",
                    revocationReason = RevokeReasonCodeEnum.Superseded,
                    operationType = OperationTypeEnum.Revoke,
                    ItemElementName = ItemChoiceType.seatId,
                    Item = seatName,
                    revocationReasonSpecified = true
                });
                return response != null && response.updateCertificateStatusResponse1.successCode < 0;
            }
            catch (Exception e)
            {
                throw e;
            }
            finally
            {
                await client.CloseAsync();
            }
        }
    }

    public static class BindingHelper
    {
        public static Binding Binding()
        {
            var binding = new BasicHttpsBinding(BasicHttpsSecurityMode.Transport);
            binding.Security.Transport.ClientCredentialType = HttpClientCredentialType.Certificate;
            return binding;
        }

        /// <summary>
        /// Used when code is deployed as an Azure Function to pull RA certificate out of Azure Key Vault
        /// </summary>
        /// <param name="credentials"></param>
        /// <returns></returns>
        public static async Task SetCredentials(this ClientCredentials credentials)
        {
            var azureServiceTokenProvider = new AzureServiceTokenProvider();
            var keyClient = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(azureServiceTokenProvider.KeyVaultTokenCallback));
            var cert = await keyClient.GetSecretAsync(Environment.GetEnvironmentVariable("vault_path", EnvironmentVariableTarget.Process),
                Environment.GetEnvironmentVariable("vault_RA", EnvironmentVariableTarget.Process));

            credentials.SetCredentials(new X509Certificate2(Convert.FromBase64String(cert.Value), "", X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable));
        }

        /// <summary>
        /// Used when RA is held locally
        /// </summary>
        /// <param name="credentials"></param>
        /// <param name="cert"></param>
        public static void SetCredentials(this ClientCredentials credentials, X509Certificate2 cert)
        {
            credentials.ClientCertificate.Certificate = cert;
        }
    }
}
