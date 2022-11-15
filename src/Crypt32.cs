using System;
using System.Runtime.InteropServices;

namespace PSSPI;

internal static class Crypt32
{
    [DllImport("Crypt32.dll")]
    public static extern bool CertFreeCertificateContext(
        IntPtr pCertContext);
}
