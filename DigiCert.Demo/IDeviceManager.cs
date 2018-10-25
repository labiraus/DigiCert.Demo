using System;
using System.Security.Cryptography.X509Certificates;

namespace DigiCert.Demo
{
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
