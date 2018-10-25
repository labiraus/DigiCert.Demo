using Microsoft.Azure.Devices;
using Microsoft.Azure.Devices.Provisioning.Client;
using Microsoft.Azure.Devices.Provisioning.Client.Transport;
using Microsoft.Azure.Devices.Shared;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace DigiCert.Demo
{
    public class Provisioning : IProvisioning
    {
        public event EventHandler<string> MessageHandler;
        private readonly string _globalDeviceEndpoint;
        private readonly string _idScope;
        private readonly string _iotHub;

        public Provisioning(IConfigurationRoot configuration) :
            this(configuration.GetConnectionString("GlobalDeviceEndpoint"), configuration.GetConnectionString("IdScope"), configuration.GetConnectionString("IoTHub"))
        {
        }

        private Provisioning(string globalDeviceEndpoint, string idScope, string iotHub)
        {
            _globalDeviceEndpoint = globalDeviceEndpoint;
            _idScope = idScope;
            _iotHub = iotHub;
        }

        public static Task<bool> ProvisionDevice(X509Certificate2 certificate, string globalDeviceEndpoint, string idScope, string iotHub)
        {
            var provisioning = new Provisioning(globalDeviceEndpoint, idScope, iotHub);
            return provisioning.ProvisionDevice(certificate);
        }

        public async Task<bool> ProvisionDevice(X509Certificate2 certificate)
        {
            handleMessage(CertificateHelper.TestCert(certificate));
            try
            {
                using (var security = new SecurityProviderX509Certificate(certificate))
                using (var transport = new ProvisioningTransportHandlerMqtt(TransportFallbackType.TcpOnly))
                {
                    ProvisioningDeviceClient provClient = ProvisioningDeviceClient.Create(_globalDeviceEndpoint, _idScope, security, transport);
                    DeviceRegistrationResult result = await provClient.RegisterAsync();
                    switch (result.Status)
                    {
                        case ProvisioningRegistrationStatusType.Assigned:
                            return true;
                        case ProvisioningRegistrationStatusType.Failed:
                        default:
                            handleMessage(result.ErrorMessage);
                            return false;
                    }
                }
            }
            catch (Exception e)
            {
                handleMessage(e.ToString());
                return false;
            }
        }

        public async Task DeleteDevice(string name)
        {
            try
            {
                using (var deviceManager = RegistryManager.CreateFromConnectionString(_iotHub))
                {
                    await deviceManager.RemoveDeviceAsync(name);
                    handleMessage($"Successfully deleted device {name}");
                }
            }
            catch (Exception e)
            {
                handleMessage(e.ToString());
            }
        }

        public async Task<bool> TestProvisioning(string name, X509Certificate2 certificate)
        {
            try
            {
                using (var deviceManager = RegistryManager.CreateFromConnectionString(_iotHub))
                {
                    var device = await deviceManager.GetDeviceAsync(name);
                    return device.Authentication.X509Thumbprint.PrimaryThumbprint == certificate.Thumbprint ||
                        device.Authentication.X509Thumbprint.SecondaryThumbprint == certificate.Thumbprint;
                }
            }
            catch (Exception e)
            {
                handleMessage(e.ToString());
                return false;
            }
        }

        public Task CreateDNSAccount(string username, string password, string masterUser, string masterPassword)
        {
            throw new NotImplementedException();
        }

        private void handleMessage(string message)
        {
            MessageHandler?.Invoke(this, message);
        }
    }

    public interface IProvisioning
    {
        event EventHandler<string> MessageHandler;
        Task<bool> ProvisionDevice(X509Certificate2 certificate);
        Task<bool> TestProvisioning(string name, X509Certificate2 certificate);
        Task DeleteDevice(string name);
    }
}
