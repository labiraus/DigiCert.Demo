using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Services.AppAuthentication;
using System;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.Threading.Tasks;

namespace DigiCert.Demo
{
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

        public static void SetCredentials(this ClientCredentials credentials, X509Certificate2 cert)
        {
            credentials.ClientCertificate.Certificate = cert;
        }
    }
}
