using System;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Security.Cryptography.X509Certificates;

namespace DigiCert.Demo
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("DigiCert demo code!");

            IConfigurationRoot configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
                .Build();

            var serviceProvider = new ServiceCollection()
                .AddSingleton<IDeviceManager, DeviceManager>()
                .AddSingleton<IProvisioning, Provisioning>()
                .AddSingleton<ICertificateService, CertificateService>()
                .AddSingleton(configuration)
                .BuildServiceProvider();

            var deviceManager = serviceProvider.GetService<IDeviceManager>();
            deviceManager.MessageHandler += message;

            deviceManager.Create("test", StoreName.My, "policy1");
            deviceManager.Provision("test", StoreName.My);
            deviceManager.TestProvisioning("test", StoreName.My);
            var iotHub = deviceManager.GetHub("test", StoreName.My);
            iotHub.StartReceiving().Start();
            iotHub.SendMessage("Test Message").Wait();
            Console.WriteLine("Press enter to continue");
            Console.ReadLine();
            iotHub.StopReceiving();
            deviceManager.Delete("test", StoreName.My);
        }

        static void message(object sender, string message)
        {
            Console.WriteLine(message);
        }
    }
}
