using Microsoft.Extensions.Configuration;
using System;
using System.Security.Cryptography.X509Certificates;

namespace DigiCert.Demo
{
    public class DeviceManager : IDeviceManager
    {
        private readonly ICertificateService _certificateService;
        private readonly IProvisioning _provisioning;
        private readonly IConfigurationRoot _configuration;
        public event EventHandler<string> MessageHandler;

        public DeviceManager(ICertificateService certificateService, IProvisioning provisioning, IConfigurationRoot configuration)
        {
            _certificateService = certificateService;
            _provisioning = provisioning;
            _configuration = configuration;
            _certificateService.MessageHandler += message;
            _provisioning.MessageHandler += message;
        }

        public void Create(string commonName, StoreName storeName, string policy)
        {
            _certificateService.Create(commonName, storeName, policy);
        }

        public void Delete(string commonName, StoreName storeName)
        {
            _certificateService.Delete(commonName, storeName);
            _certificateService.Delete(commonName);
        }

        public async void Provision(string commonName, StoreName storeName)
        {
            var cert = CertificateHelper.Get(storeName, commonName, _configuration["CACommonName"]);
            await _provisioning.ProvisionDevice(cert);
        }

        public async void TestProvisioning(string commonName, StoreName storeName)
        {
            var cert = CertificateHelper.Get(storeName, commonName, _configuration["CACommonName"]);
            await _provisioning.TestProvisioning(commonName, cert);
        }

        public IoTHub GetHub(string commonName, StoreName storeName)
        {
            var cert = CertificateHelper.Get(storeName, commonName, _configuration["CACommonName"]);
            var hub = new IoTHub(message);
            hub.InitAsync(_configuration, cert).Wait();
            return hub;
        }

        void message(object sender, string message)
        {
            handleMessage(message);
        }

        private void handleMessage(string message)
        {
            MessageHandler?.Invoke(this, message);
        }
    }

    public interface IDeviceManager
    {
        event EventHandler<string> MessageHandler;
        void Create(string commonName, StoreName storeName, string policy);
        void Provision(string commonName, StoreName storeName);
        void TestProvisioning(string commonName, StoreName storeName);
        IoTHub GetHub(string commonName, StoreName storeName);
        void Delete(string commonName, StoreName storeName);
    }
}
