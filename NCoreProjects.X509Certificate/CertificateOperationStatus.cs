using System;

namespace NCoreProjects.X509Certificate
{
    public class CertificateOperationStatus
    {
        public Status Status { get; set; }
        public string Thumbprint { get; set; }
        public string Subject { get; set; }

        public DateTime? Expiry { get; set; }

        public string Message { get; set; }
    }

    public enum Status
    {
        Error,
        Ok
    }
}
