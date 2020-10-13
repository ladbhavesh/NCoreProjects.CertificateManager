using Microsoft.Win32.SafeHandles;
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace NCoreProjects.X509Certificate
{
    public interface IImpersonate
    {
        void ImpersonateAction(string domain, string username, string password, Action funcToImpersobate);
    }


    public class Impersonate : IImpersonate
    {
        /*https://docs.microsoft.com/en-us/dotnet/api/system.security.principal.windowsidentity.impersonate?redirectedfrom=MSDN&view=netframework-4.8#System_Security_Principal_WindowsIdentity_Impersonate_System_IntPtr_*/
        //https://docs.microsoft.com/en-us/dotnet/api/system.security.principal.windowsidentity.runimpersonated?view=netframework-4.8
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern bool LogonUser(String lpszUsername, String lpszDomain, String lpszPassword,int dwLogonType, int dwLogonProvider, out SafeAccessTokenHandle phToken);



        private const int LOGON32_PROVIDER_DEFAULT = 0;
        //This parameter causes LogonUser to create a primary token.
        const int LOGON32_LOGON_INTERACTIVE = 2;
        const int LOGON32_LOGON_NETWORK = 3;
        const int LOGON32_LOGON_BATCH = 4;
        const int LOGON32_LOGON_SERVICE = 5;
        const int LOGON32_LOGON_UNLOCK = 7;
        const int LOGON32_LOGON_NETWORK_CLEARTEXT = 8;
        const int LOGON32_LOGON_NEW_CREDENTIALS = 9;
        //private const int LOGON32_LOGON_INTERACTIVE = 9;// 2;

        public void ImpersonateAction(string domain, string username, string password, Action funcToImpersonate)
        {
            SafeAccessTokenHandle safeAccessTokenHandle;
            bool success = LogonUser(username, domain, password, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT,out safeAccessTokenHandle);


            if (!success)
            {
                int ret = Marshal.GetLastWin32Error();
                throw new Win32Exception($"LogonUser failed with error code : {ret}");
            }

            WindowsIdentity.RunImpersonated(safeAccessTokenHandle, funcToImpersonate);

        }
    }

   

}
