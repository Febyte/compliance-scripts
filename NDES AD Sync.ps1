# This script makes several assumptions:
# * Intune is requesting device certificates.
# * CNs are based on device names.
# * SPNs are based on the Intune Device IDs.

function ConvertTo-AltSecurityIdentity
{
	Param($IssuerSubject, $SerialNumber)

	# Reverse the hex-formatted byte array.
	$SerialArray = for ($i = $SerialNumber.Length - 2; $i -ge 0; $i -= 2) { $SerialNumber[$i] + $SerialNumber[$i+1] }
	$SerialReversed = $SerialArray -join ''

	# Reverse the comma-separated Subject DN.
	$IssuerParts = $IssuerSubject.Split(',')
	[Array]::Reverse($IssuerParts)
	$IssuerReversed = $IssuerParts -join ','

	# Post-KB5014754 strong mapping.
	"X509:<I>$IssuerReversed<SR>$SerialReversed"
}

function Update-ADObjectSupplicant
{
	Param($Identity, $IssuerSubject, $SerialNumber, $DeviceId)

	$AltSecurityIdentity = ConvertTo-AltSecurityIdentity -IssuerSubject $IssuerSubject -SerialNumber $SerialNumber

	Set-ADComputer -Identity $Identity -Add @{
		altSecurityIdentities = $AltSecurityIdentity
		servicePrincipalName = "HOST/$DeviceId"
	}
}

function New-ADObjectSupplicant
{
	Param($CommonName, $ADPath, $IssuerSubject, $SerialNumber, $DeviceId)

	$AltSecurityIdentity = ConvertTo-AltSecurityIdentity -IssuerSubject $IssuerSubject -SerialNumber $SerialNumber

	New-ADComputer -Name $CommonName -Path $ADPath -ServicePrincipalNames "HOST/$DeviceId" -OtherAttributes @{
		altSecurityIdentities = $AltSecurityIdentity
	}
}

function Find-ADObjectSupplicant
{
	Param($DeviceId)

	Get-ADComputer -LDAPFilter "(servicePrincipalName:=HOST/$DeviceId)"
}

function Get-SupplicantCertificate
{
	Param($ConnectionString, $TemplateOid)

	$CA = New-Object -ComObject 'CertificateAuthority.View'
	$CA.OpenConnection($ConnectionString)

	$CA.SetResultColumnCount(4)
	$CA.SetResultColumn(9) # Request Disposition
	$CA.SetResultColumn(46) # Certificate Template
	$CA.SetResultColumn(50) # Serial Number
	$CA.SetResultColumn(66) # Common Name

	$Row = $CA.OpenView()
	while ($Row.Next() -ne -1)
	{
		$RowObj = [PSCustomObject]::new()

		$Column = $Row.EnumCertViewColumn()
		while ($Column.Next() -ne -1)
		{
			$RowObj | Add-Member -NotePropertyName $Column.GetName() -NotePropertyValue $Column.GetValue(0)
		}

		# Filter out non-NDES certs and revoked certs.
		if ($RowObj.CertificateTemplate -ne $TemplateOid -or $RowObj.'Request.Disposition' -ne 20)
		{
			continue
		}
		
		$Attribute = $Row.EnumCertViewAttribute(0)
		$AttributeObj = [PSCustomObject]::new()
		while ($Attribute.Next() -ne -1)
		{
			$AttributeObj | Add-Member -NotePropertyName $Attribute.GetName() -NotePropertyValue $Attribute.GetValue()
		}

		$RowObj | Add-Member -NotePropertyName 'Attributes' -NotePropertyValue $AttributeObj

		$Extension = $Row.EnumCertViewExtension(0)
		$ExtensionObj = [PSCustomObject]::new()
		while ($Extension.Next() -ne -1)
		{
			$ExtensionOid = $Extension.GetName()
			$ExtensionBin = [System.Convert]::FromBase64String($Extension.GetValue(0x00000003, 0x01))
			$ExtensionData = [System.Security.Cryptography.AsnEncodedData]::new($ExtensionOid, $ExtensionBin)

			# output "DNS Name=san1.example.com\r\nDNS Name=san2.example.com\r\n" on .NET Core 2.2 Windows
			# output "DNS:san1.example.com, DNS:san2.example.com" on .NET Core 2.2 Linux
			$FormattedExtension = $ExtensionData.Format($false)

			# SAN
			if ($ExtensionOid -eq '2.5.29.17')
			{
				# JAS: There should only be one DNS Name, and this will only work on Windows.
				if ($FormattedExtension -match 'DNS Name=.*')
				{
					$Selection = $FormattedExtension | Select-String -Pattern 'DNS Name=(.*)'
					$DnsName = $Selection.Matches.Groups[1].Value
					$FormattedExtension = [PSCustomObject] @{ DnsName = $DnsName }
				}
				elseif ($FormattedExtension -match 'Other Name:Principal Name=.*')
				{
					$Selection = $FormattedExtension | Select-String -Pattern 'Other Name:Principal Name=(.*)'
					$Upn = $Selection.Matches.Groups[1].Value
					$FormattedExtension = [PSCustomObject] @{ Upn = $Upn }
				}
			}

			$ExtensionObj | Add-Member -NotePropertyName $ExtensionData.Oid.FriendlyName -NotePropertyValue $FormattedExtension
		}

		$RowObj | Add-Member -NotePropertyName 'Extensions' -NotePropertyValue $ExtensionObj -PassThru | `
			Select-Object -Property 'CommonName', 'SerialNumber', @{Name='SAN'; Expression={$_.Extensions.'Subject Alternative Name'}}
	}
}
