<#

.SYNOPSIS
Powershell script for CSV import (creation and update) in Dynamics 365 (v8+) for OnPremise or Online

.DESCRIPTION
The mapping of the field is automatic (by checking the entity metadata in CRM)
To update a record provide the Guid of the record, for creation leave the field empty
For Picklist field provide the CRM Optionset int value 
For Lookup value provide the Guid of the record
A contacts.csv example file is provided for demonstration
A success_date.log and errors_date.log files are created during import with the succes and errors records.

.EXAMPLE
./dynamics365import.ps1 -url https://mycrmurl.crm4.dynamics.com -username user@mydomain.fr -password mypassword -entity myentity -file myimportfile.csv

With no credentials in cmd (will be asked more securely by Windows prompt) :
./dynamics365import.ps1 -url https://mycrmurl.crm4.dynamics.com -entity myentity -file myimportfile.csv


.NOTES


.LINK
https://github.com/michaelsazbon/dynamics365import

#>

[CmdletBinding()]
param(
    [parameter(mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$url,
    [string]$username,
    [string]$password,
    [parameter(mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$entity,
    [parameter(mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$file
)

function Get-AttributeValue {
    param (
        $attributeName,
        $attributeValue
    )

    if($attributeValue -eq $null -or $attributeValue -eq "") {
        return $null
    }

    if($attributes.ContainsKey($attributeName)) {

        $attribute = $attributes[$attributeName]

    } else {

        $attribute = $EntityMetadata | Where-Object { $_.LogicalName -eq $attributeName }

        $attributes[$attributeName] = $attribute
    }
    

    switch ($attribute.AttributeType) {
        "Lookup" { 
            $lookup = New-Object Microsoft.Xrm.Sdk.EntityReference($attribute.Targets[0], [Guid]::Parse($attributeValue))
            $attribute = [Microsoft.Xrm.Sdk.EntityReference]$lookup
        }
        "Customer" { 
            $lookup = New-Object Microsoft.Xrm.Sdk.EntityReference($attribute.Targets[0], [Guid]::Parse($attributeValue))
            $attribute = [Microsoft.Xrm.Sdk.EntityReference]$lookup
        }
        "Picklist" { 
            $picklist = New-Object Microsoft.Xrm.Sdk.OptionSetValue([int]$attributeValue)
            $attribute = [Microsoft.Xrm.Sdk.OptionSetValue]$picklist
         }
        "Boolean" { 
            $attribute = [bool]$attributeValue
         }
        "DateTime" { 
            $attribute = [DateTime]$attributeValue
         }
         "Integer" {
            $attribute = [int]$attributeValue
         }
         "Decimal" {
            $attribute = [decimal]$attributeValue
         }
        Default { $attribute = $attributeValue}
    }
    
    return $attribute
}



Add-Type -Path "Microsoft.Crm.Sdk.Proxy.dll"
Add-Type -Path "Microsoft.Xrm.Sdk.dll"

[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;

[void][System.Reflection.Assembly]::LoadWithPartialName("system.servicemodel")

$date = (Get-Date).ToString("yyyy-MM-dd-HH.mm.ss")

$CrmURL = "$url/XRMServices/2011/Organization.svc";

$entityKey = $entity + "id"

$clientCredentials = new-object System.ServiceModel.Description.ClientCredentials

if($username -ne "" -and $password -ne "") {
    $clientCredentials.UserName.UserName = $username
    $clientCredentials.UserName.Password = $password
} else {
    $creds = Get-Credential
    $clientCredentials.UserName.UserName = $creds.UserName 
    $clientCredentials.UserName.Password = $creds.GetNetworkCredential().Password
}

$service = new-object Microsoft.Xrm.Sdk.Client.OrganizationServiceProxy($CrmURL, $null, $clientCredentials, $null)
$service.Timeout = new-object System.Timespan(0, 10, 0)

#$request = new-object Microsoft.Crm.Sdk.Messages.WhoAmIRequest
#$service.Execute($request)

$retrieveEntityRequest = new-object Microsoft.Xrm.Sdk.Messages.RetrieveEntityRequest
$retrieveEntityRequest.EntityFilters = [Microsoft.Xrm.Sdk.Metadata.EntityFilters]::Attributes
$retrieveEntityRequest.LogicalName = $entity

$retrieveAccountEntityResponse = $service.Execute($retrieveEntityRequest)
$Global:EntityMetadata = $retrieveAccountEntityResponse.EntityMetadata.Attributes
$Global:attributes = @{}

$records = Import-Csv $file -Delimiter ";"
$total = $records.Count
$i = 1


$records | Foreach-Object {

    $line = $_
    
    $entityrecord = New-Object Microsoft.Xrm.Sdk.Entity($entity)

    if($_.$entityKey -ne "") {
        $entityrecord.Id = [Guid]::Parse($_.$entityKey) 
    }   

    foreach($property in $line.psobject.properties.name) {

        if($property -ne $entityKey) {
            $attributeValue = Get-AttributeValue -attributeName $property -attributeValue $line.$property
            $entityrecord.Attributes[$property] = $attributeValue
        }
    }
 
    Write-host ('Processing record : ({0} / {1})' -f $i, $total)

    try {

        if($_.$entityKey -ne "") {
            $service.Update($entityrecord)
        } else {
            $service.Create($entityrecord)
        }
        
        $line | Export-Csv -Path "success_$date.csv" -Delimiter ";" -Append -NoTypeInformation
    }
    catch {

        
        $line | Add-Member -MemberType NoteProperty -Name "Error" -Value $_.Exception.Message

        $line | Export-Csv -Path "errors_$date.csv" -Delimiter ";" -Append -NoTypeInformation
    }

    $i++
    
}
