using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace DigiCert.Demo
{
    public static class CertificateHelper
    {
        public static X509Certificate2 Get(StoreName name, string subjectPart, string caCommonName)
        {
            return Get(new CertificateDescription(name, subjectPart, caCommonName));
        }

        public static X509Certificate2 Get(CertificateDescription certDesc)
        {
            certDesc.Reference = "ref";
            return Get(new List<CertificateDescription>() { certDesc })[certDesc.Reference];
        }

        public static Dictionary<string, X509Certificate2> Get(IEnumerable<CertificateDescription> certs)
        {
            var output = certs.ToDictionary(x => x.Reference, x => (X509Certificate2)null);
            foreach (var certDesc in certs)
                using (var store = new X509Store(certDesc.StoreName, StoreLocation.LocalMachine))
                {
                    store.Open(OpenFlags.ReadOnly);
                    foreach (var cert in store.Certificates)
                        if (cert.Issuer == certDesc.CACommonName && cert.Subject.Contains(certDesc.SubjectPart))
                            output[certDesc.Reference] = cert;
                    store.Close();
                }
            return output;
        }

        public static List<string> PurgeCertificates(StoreName name, string subjectPart = null, string caCommonName = null)
        {
            var certs = new X509Certificate2Collection();
            var serialNumbers = new List<string>();
            using (var store = new X509Store(name, StoreLocation.LocalMachine))
            {
                store.Open(OpenFlags.ReadWrite);
                foreach (var cert in store.Certificates)
                {
                    if ((subjectPart == null || cert.Subject.Contains(subjectPart)) &&
                        (caCommonName == null || cert.Issuer == caCommonName))
                    {
                        certs.Add(cert);
                        serialNumbers.Add(cert.SerialNumber);
                    }
                }
                store.RemoveRange(certs);
                store.Close();
            }
            return serialNumbers;
        }

        public static void PurgeCertificate(X509Certificate2 certificate, StoreName storeName)
        {
            using (var store = new X509Store(storeName, StoreLocation.LocalMachine))
            {
                store.Open(OpenFlags.ReadWrite);
                store.Remove(certificate);
                store.Close();
            }
        }

        public static void AddCertificate(X509Certificate2 cert, StoreName storeName)
        {
            using (var store = new X509Store(storeName, StoreLocation.LocalMachine))
            {
                store.Open(OpenFlags.ReadWrite);
                store.Add(cert);
                store.Close();
            }
        }

        public static string TestCert(X509Certificate2 cert)
        {
            var output = new StringBuilder();
            X509Chain chain = new X509Chain();

            try
            {
                var chainBuilt = chain.Build(cert);
                output.AppendLine(string.Format("Chain building status: {0}", chainBuilt));

                if (chainBuilt == false)
                    foreach (X509ChainStatus chainStatus in chain.ChainStatus)
                        output.AppendLine(string.Format("Chain error: {0} {1}", chainStatus.Status, chainStatus.StatusInformation));
            }
            catch (Exception ex)
            {
                output.AppendLine(ex.ToString());
            }
            return output.ToString();
        }
    }
    public class CertificateDescription
    {
        public CertificateDescription(StoreName name, string subjectPart, string caCommonName)
        {
            CACommonName = caCommonName;
            StoreName = name;
            SubjectPart = subjectPart;
        }
        public StoreName StoreName { get; set; }
        public string CACommonName { get; set; }
        public string SubjectPart { get; set; }
        public string Reference { get; set; }
    }
}
