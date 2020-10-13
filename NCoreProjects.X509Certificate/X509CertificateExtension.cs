using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using static System.Environment;

namespace NCoreProjects.X509Certificate
{
    public static class X509CertificateExtension
    {
        public static void DeleteCertificatesIfExist(this X509Store store, string subject, StoreLocation storeLocation, StoreName storeName)
        {
           
               
                    var certs = store.Certificates.Find(X509FindType.FindBySubjectName, subject, false);

                    foreach(var cert in certs)
                    {
                        store.Remove(cert);
                    }
                  
                
           
        }

        public static CertificateOperationStatus AddCertificate(this X509Store store, byte[] rawData, string password, bool privateKeyAccessToEveryOne=false)
        {
            
                var cert = new X509Certificate2(rawData, password,X509KeyStorageFlags.Exportable|X509KeyStorageFlags.MachineKeySet|X509KeyStorageFlags.PersistKeySet);
                store.Add(cert);

                if (privateKeyAccessToEveryOne)
                {
                    var rsaKey = cert.GetRSAPrivateKey();
                    if (rsaKey != null)
                    {
                        var rsaCng = rsaKey as RSACng;
                        if (rsaCng != null)
                        {
                            var key = rsaCng.Key;
                             

                            var file = @$"{Environment.GetFolderPath(SpecialFolder.CommonApplicationData)}\Microsoft\Crypto\Keys\{key.UniqueName}";

                            if (!File.Exists(file))
                            {
                                file = @$"{Environment.GetFolderPath(SpecialFolder.CommonApplicationData)}\Microsoft\RSA\MachineKeys\{key.UniqueName}";

                                if (File.Exists(file))
                                {
                                    GrantFullAccess(file);

                                    return new CertificateOperationStatus
                                    {
                                        Status = Status.Ok,
                                        Expiry = cert.NotAfter,
                                        Thumbprint = cert.Thumbprint,
                                        Subject = cert.Subject
                                    };
                                }
                            }
                            else
                            {
                                GrantFullAccess(file);
                                return new CertificateOperationStatus
                                {
                                    Status = Status.Ok,
                                    Expiry = cert.NotAfter,
                                    Thumbprint = cert.Thumbprint,
                                    Subject = cert.Subject
                                };
                            }
                        }
                    }

                    throw new InvalidOperationException($"Unable to add certificate properly");
                    
                }
                else
                {
                    return new CertificateOperationStatus
                    {
                        Status = Status.Ok,
                        Expiry = cert.NotAfter,
                        Thumbprint = cert.Thumbprint,
                        Subject = cert.Subject
                    };
                }
                
            
        }

        private static void GrantFullAccess(string fullPath)
        {
            DirectoryInfo dInfo = new DirectoryInfo(fullPath);
            DirectorySecurity dSecurity = dInfo.GetAccessControl();
            dSecurity.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                FileSystemRights.FullControl, AccessControlType.Allow));
            dInfo.SetAccessControl(dSecurity);
        }
    }
}
