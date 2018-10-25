using DigiCert.Demo.CertificateManagement;
using DigiCert.Demo.Enrollment;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
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
}
