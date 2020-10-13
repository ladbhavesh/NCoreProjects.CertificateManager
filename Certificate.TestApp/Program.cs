using NCoreProjects.X509Certificate;
using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;
using System.Security.Permissions;
using System.Security.Principal;

namespace ConsoleApp1
{
    class Program
    {
        private static void AddCerts()
        {
            using (var store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
            {
             
                store.Open(OpenFlags.ReadWrite);

                      //var cert = store.Certificates.Find(X509FindType.FindBySubjectName, "mysite.local", false)[0];

                //var cert = new X509Certificate2(File.ReadAllBytes(@"C:\Users\Dell\Desktop\test.pfx"), "test123",
                //    X509KeyStorageFlags.Exportable);
                store.AddCertificate(File.ReadAllBytes(@"C:\Users\Dell\Desktop\test.pfx"), "test123", true);

                // store.Add(cert);

                //var x = cert.GetRSAPrivateKey();
                //var key = ((System.Security.Cryptography.RSACng)x).Key;
                //Console.WriteLine(key.UniqueName);

                //var file = @$"C:\ProgramData\Microsoft\Crypto\Keys\{key.UniqueName}";

                //if (File.Exists(file))
                //{
                //    // GrantAccess(file);
                //}

                // System.Security.Cryptography.CngKey

                store.Close();
            }
        }

        [PermissionSetAttribute(SecurityAction.Demand, Name = "FullTrust")]
        static void Main(string[] args)
        {
            Impersonate imp = new Impersonate();
            //AddCerts();
           imp.ImpersonateAction(".", "testuser777", "test123", AddCerts);
                Console.WriteLine("Hello World!");
        }

        private static void GrantAccess(string fullPath)
        {
            DirectoryInfo dInfo = new DirectoryInfo(fullPath);
            DirectorySecurity dSecurity = dInfo.GetAccessControl();
            dSecurity.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), 
                FileSystemRights.FullControl, AccessControlType.Allow));
            dInfo.SetAccessControl(dSecurity);
        }
    }
}
