using System.Security.Cryptography.X509Certificates;

namespace DigiCert.Demo
{
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
