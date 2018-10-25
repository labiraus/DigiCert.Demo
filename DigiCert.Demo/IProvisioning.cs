using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace DigiCert.Demo
{
    public interface IProvisioning
    {
        event EventHandler<string> MessageHandler;
        Task<bool> ProvisionDevice(X509Certificate2 certificate);
        Task<bool> TestProvisioning(string name, X509Certificate2 certificate);
        Task DeleteDevice(string name);
    }
}
