---
external help file: PSSPI.dll-Help.xml
Module Name: PSSPI
online version: https://www.github.com/jborean93/PSSPI/blob/main/docs/en-US/Get-SSPIPackage.md
schema: 2.0.0
---

# Get-SSPIPackage

## SYNOPSIS
Gets security package information.

## SYNTAX

```
Get-SSPIPackage [-Name <String[]>] [<CommonParameters>]
```

## DESCRIPTION
Gets information about the installed security packages that SSPI can use.

## EXAMPLES

### Example 1: Get all installed security packages
```powershell
PS C:\> Get-SSPIPackage
```

Get the details of all the installed security packages.

### Example 2: Get information about a specific security package
```powershell
PS C:\> Get-SSPIPackage -Name Negotiate, Kerberos
```

Get the details of the `Negotiate` and `Kerberos` security package.

## PARAMETERS

### -Name
Get the details of the security packages specified.
If omitted then all security packages will be returned.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None
## OUTPUTS

### SSPI.SecPackageInfo
The security package information. This object has the following properties:

+ `Name`: The name of the security package.

+ `Comment`: Additional information of the security package.

+ `Capabilities`: Set of bit flags that describes the capabilities of the security package.

+ `Version`: Specifies the version of the package protocol. Must be 1.

+ `RPCID`: Specifies a DCE RPC identifier, if appropriate. If the package does not implement one of the DCE registered security systems, the reserved value SECPKG_ID_NONE is used.

+ `MaxTokenSize`: Specifies the maximum size, in bytes, of the token.

## NOTES

## RELATED LINKS

[EnumerateSecurityPackagesW](https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-enumeratesecuritypackagesw)
[QuerySecurityPackageInfoW](https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-querysecuritypackageinfow)
[SecPkgInfoW](https://docs.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secpkginfow)
