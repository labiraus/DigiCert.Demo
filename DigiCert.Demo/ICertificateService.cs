using System;
using System.Security.Cryptography.X509Certificates;

namespace DigiCert.Demo
{
    public interface ICertificateService
    {
        event EventHandler<string> MessageHandler;
        void Create(string commonName, StoreName storeName, string policy);
        void Delete(string commonName, StoreName storeName);
        void Delete(string commonName);
    }
}
