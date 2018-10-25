using Microsoft.Extensions.Configuration;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace DigiCert.Demo
{
    public class CertificateService : ICertificateService
    {
        private readonly IConfigurationRoot _configuration;
        private readonly X509Certificate2 _ra;

        public CertificateService(IConfigurationRoot configuration)
        {
            _configuration = configuration;
            _ra = CertificateHelper.Get(StoreName.My, _configuration["RACommonName"], _configuration["CACommonName"]);
        }

        public event EventHandler<string> MessageHandler;

        /// <summary>
        /// Creates a CSR, has it signed by the MPKI and installs the resultant certificate
        /// </summary>
        /// <param name="commonName"></param>
        /// <param name="storeName"></param>
        /// <param name="policy"></param>
        public async void Create(string commonName, StoreName storeName, string policy)
        {
            var guid = Guid.NewGuid();
            var file = @"CertBundle" + guid.ToString() + ".pfx";
            byte[] csr = null;
            try
            {
                var rsaKeyPairGenerator = new RsaKeyPairGenerator();
                var genParam = new RsaKeyGenerationParameters(BigInteger.ValueOf(0x10001), new SecureRandom(), 2048, 128);
                rsaKeyPairGenerator.Init(genParam);
                AsymmetricCipherKeyPair keyPair = rsaKeyPairGenerator.GenerateKeyPair();

                var attrs = new Dictionary<DerObjectIdentifier, string> { { X509Name.CN, commonName } };
                var subject = new X509Name(attrs.Keys.ToList(), attrs);
                csr = new Pkcs10CertificationRequest(PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id, subject, keyPair.Public, null, keyPair.Private).GetEncoded();
                var signedCert = await RAConnector.Get(commonName, Convert.ToBase64String(csr), _configuration[policy], _configuration["webMaster"], _ra);

                var signedX509Cert = new X509CertificateParser().ReadCertificate(signedCert);
                X509CertificateEntry certEntry = new X509CertificateEntry(signedX509Cert);

                // Prepare the pkcs12 certificate store
                Pkcs12Store tempStore = new Pkcs12StoreBuilder().Build();

                // Bundle together the private key, signed certificate and CA
                tempStore.SetKeyEntry(signedX509Cert.SubjectDN.ToString() + "_key", new AsymmetricKeyEntry(keyPair.Private), new X509CertificateEntry[] { certEntry });

                // Finally save the bundle as a PFX file
                using (var filestream = new FileStream(file, FileMode.Create, FileAccess.ReadWrite))
                    tempStore.Save(filestream, "password".ToCharArray(), new SecureRandom());

                var finalCert = new X509Certificate2(file, "password", X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);
                CertificateHelper.AddCertificate(finalCert, storeName);
            }
            catch (Exception e)
            {
                handleMessage(e.Message);
            }
            finally
            {
                File.Delete(file);
            }
        }
        
        /// <summary>
        /// Removes the seat name from the MPKI
        /// </summary>
        /// <param name="commonName"></param>
        public async void Delete(string commonName)
        {
            await RAConnector.Delete(commonName, _ra);
        }

        /// <summary>
        /// Deletes certificates off of the device and removes them from the MPKI by serial number
        /// </summary>
        /// <param name="commonName"></param>
        /// <param name="storeName"></param>
        public async void Delete(string commonName, StoreName storeName)
        {
            await RAConnector.Delete(CertificateHelper.PurgeCertificates(storeName, commonName, _configuration["CACommonName"]), _ra);
        }

        private void handleMessage(string message)
        {
            MessageHandler?.Invoke(this, message);
        }
    }
    public interface ICertificateService
    {
        event EventHandler<string> MessageHandler;
        void Create(string commonName, StoreName storeName, string policy);
        void Delete(string commonName, StoreName storeName);
        void Delete(string commonName);
    }
}
