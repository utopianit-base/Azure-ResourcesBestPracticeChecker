# Azure Resources Best Practice Naming Convention Checker Script
#
# Purpose: Gets a list of the Microsoft Best Practice Naming Conventions from the website and then
# checks all subscriptions and all resources against the naming conventions.
# The naming convention CSV that's generated the first time can be amended as necessary to provide
# a baseline report on compliance to best practice naming for the organisation.
#
# Version : 19/05/2021
# Author  : Chris Harris (chris@utopianit.co.uk)
#

function require-Module {
    param ([string]$Name,[boolean]$isInteractive=$true,[boolean]$AlwaysUpdate=$false)

    if((Get-Module $Name) -and $AlwaysUpdate) {
        write-host "Module found. Forcing Update of $Name and importing as current user." -ForegroundColor Cyan
        update-module $Name -ErrorAction SilentlyContinue
        import-module $Name -ErrorAction SilentlyContinue

        if (!(Get-Module $Name)) {
            write-host "Failed to install or import module $Name." -ForegroundColor Red
            if(!$isInteractive) { return $false }
        } else {
            write-host "Successfully imported module $Name." -ForegroundColor Green
            if(!$isInteractive) { return $true }
        }
    } elseif (!(Get-Module $Name)) {
        write-host "Module $Name not imported." -ForegroundColor Cyan
        import-module $Name -ErrorAction SilentlyContinue
        if (!(Get-Module $Name)) {
            write-host "Module not found. Installing $Name and importing as current user." -ForegroundColor Yellow
            install-module $Name -Scope CurrentUser -ErrorAction SilentlyContinue
            import-module $Name -ErrorAction SilentlyContinue
            if (!(Get-Module $Name)) {
                write-host "Failed to install or import module $Name." -ForegroundColor Red
                if(!$isInteractive) { return $false }
            } else {
                write-host "Successfully imported module $Name." -ForegroundColor Green
                if(!$isInteractive) { return $true }
            }
        } else {
                write-host "Successfully imported module $Name." -ForegroundColor Green
                if(!$isInteractive) { return $true }
        }
    } else {
        write-host "Module $Name already imported." -ForegroundColor Green       
    }
}

Function Use-CorpProxy {
    # Set to use default proxy creds when making internet calls. Relies on current user IE Proxy settings
    [System.Net.WebRequest]::DefaultWebProxy.Credentials =  [System.Net.CredentialCache]::DefaultCredentials

    # Ignore Proxy Self-Signed Cert if required (for HTTPS Inspection Proxies)
    if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
    {
$certCallback = @"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        public static void Ignore()
        {
            if(ServicePointManager.ServerCertificateValidationCallback ==null)
            {
                ServicePointManager.ServerCertificateValidationCallback += 
                    delegate
                    (
                        Object obj, 
                        X509Certificate certificate, 
                        X509Chain chain, 
                        SslPolicyErrors errors
                    )
                    {
                        return true;
                    };
            }
        }
    }
"@
        Add-Type $certCallback
    }
    [ServerCertificateValidationCallback]::Ignore()
}

function errorAndExit([string]$message)
{
    #logError $message
    if ($Host.Name -eq 'Windows PowerShell ISE Host') {
        throw $message
    } else {
        exit 1
    }
}

function require-AzConnect {
    # Connect to Azure (az Module) manually as an appropriate Administrative user (Supportd MFA)
    $AzConnection = Get-AzContext -ErrorAction SilentlyContinue
    if(-not ($AzConnection.Tenant.Id)) {
        $AzConnection = Connect-AzAccount
        $AzConnectionTest = Get-AzContext -ErrorAction SilentlyContinue
        if($AzConnectionTest.Tenant.Id) {
            write-host "Logged into Azure (az) as $($AzConnectionTest.Account.Id) successfully" -ForegroundColor Green
        } else {
            write-host "Connect into Azure (az) failed" -ForegroundColor Red
        }
    } else {
        write-host "Already logged into Azure (az) as $($AzConnection.Account.Id)" -ForegroundColor Green
    }
}


function Set-Subscription {
    param ([string]$Subscription)
    write-host "Selecting $Subscription as default Azure subscription" -ForegroundColor cyan
    $sub = Select-AzSubscription $Subscription -ErrorAction SilentlyContinue
    if($sub.Subscription.Name -ne $Subscription) {
            Write-host "Failed to select subscription $Subscription" -Verbose -ForegroundColor red
            errorAndExit -message "Failed to select subscription $Subscription"
    }
}

function Get-MSResourceBestPracticePSO() {
    $MSBESTPRACTICES='https://docs.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/resource-abbreviations'
    $MSBestPracticesScrape=Invoke-WebRequest -Uri $MSBESTPRACTICES -UseBasicParsing

    #<tr>
    #<td>Azure SQL Data Warehouse</td>
    #<td><code>Microsoft.Sql/servers</code></td>
    #<td><code>sqldw-</code></td>
    #</tr>

    if($MSBestPracticesScrape.StatusCode -ne 200) {
        Write-Error "Failed to get MS Naming Convention Best Practice Data. returned Code $($MSBestPracticesScrape.StatusCode)"
        Return
    }

    $AllLines = @()
    $NamingMatch = "^<td>([A-Z\s]+)|^<td><code>([A-Z\-]+)<|^<td><code>([A-Z\s./]+)<"
    $Content = $MSBestPracticesScrape.Content.Split("`n")
    $NamingConventionItems = @()

    ForEach($Line in $Content ) {
        $Line = $Line.Trim()
        #write-host "$Line"

        if($Line -match $NamingMatch) {
          if($Matches) {
              #write-host "Matched = $Line"
              if($Matches[1]) {
                $ResourceType = $Matches[1]
              } elseif($Matches[2] -and $ResourceCode) {
                $ResourcePrefix = $Matches[2]
              } elseif($Matches[3] -and $ResourceType) {
                $ResourceCode = $Matches[3]
              }
          }

          if($ResourceType -and $ResourcePrefix -and $ResourceCode) {
                $obj = New-Object PSObject
                $obj | Add-Member NoteProperty -name ResourceType -value $ResourceType
                $obj | Add-Member NoteProperty -name ResourcePrefix -value $ResourcePrefix
                $obj | Add-Member NoteProperty -name ResourceCode -value $ResourceCode

            $NamingConventionItems += $obj

            $ResourceType = ''
            $ResourceCode = ''
            $ResourcePrefix = ''
          }
        }
    }

    if($NamingConventionItems) { Return $NamingConventionItems | Sort ResourceType }
}


# Test that the ResourceName matches a valid naming convention.
# If it does match, based on the code, return PSO with the Type (Display Name) and a Status of Valid
# If it does not match, return PSO with the Possible Types (Display Names) and a Status of Invalid
# If it doesn't have any naming conventions for that type, return PSO with the Type as Unknown and a Status of Valid (Default Pass)
#
Function Test-MSResourceNamingConvention([string]$ResourceName,[string]$ResourceCode,[PSObject]$NamingConventionPSO) {
    $ValidNamingConventions = $NamingConventionPSO | Where ResourceCode -eq $ResourceCode

    if($ValidNamingConventions) {
        #$PrimaryResourceType = $ValidNamingConventions[0].ResourceType
    
        ForEach($NamingConvention in $ValidNamingConventions) {
            # Create Regex Match for ResourceType (Prefix)
            $NamingConventionMatch = "^$($NamingConvention.ResourcePrefix)"

            if($ResourceName -match $NamingConventionMatch) {
                $obj = New-Object PSObject
                $obj | Add-Member NoteProperty -name ExpectedPrefix -value $NamingConvention.ResourcePrefix
                $obj | Add-Member NoteProperty -name ResourceType -value $NamingConvention.ResourceType
                $obj | Add-Member NoteProperty -name ResourceStatus -value 'Valid'
                Return $obj
            }
        }

        $obj = New-Object PSObject
        $ValidResourceTypes = ([array]$ValidNamingConventions | Select ResourceType).ResourceType -join ', '
        $ValidResourcePrefixes = ([array]$ValidNamingConventions | Select ResourcePrefix).ResourcePrefix -join ', '
        #write-host $ValidResourceTypes

        $obj | Add-Member NoteProperty -name ExpectedPrefix -value $ValidResourcePrefixes
        $obj | Add-Member NoteProperty -name ResourceType -value $ValidResourceTypes
        $obj | Add-Member NoteProperty -name ResourceStatus -value 'Invalid'
        Return $obj

    } else {
        #write-host "Unknown Resource Code for $ResourceCode. No naming conventions found" -ForegroundColor Yellow
        $obj = New-Object PSObject
        $obj | Add-Member NoteProperty -name ExpectedPrefix -value 'Unknown'
        $obj | Add-Member NoteProperty -name ResourceType -value $ResourceCode
        $obj | Add-Member NoteProperty -name ResourceStatus -value 'Valid'
        Return $obj
    }

}

Function Add-BestPracticeReportEntry($Subscription,$ResourceGroup,$ResourceName,$ResourceType,$ExpectedPrefix,$ResourceStatus){
        $obj = New-Object PSObject
        $obj | Add-Member NoteProperty -name Subscription -value $Subscription
        $obj | Add-Member NoteProperty -name ResourceGroup -value $ResourceGroup
        $obj | Add-Member NoteProperty -name ResourceName -value $ResourceName
        $obj | Add-Member NoteProperty -name ResourceType -value $ResourceType
        $obj | Add-Member NoteProperty -name ExpectedPrefix -value $ExpectedPrefix
        $obj | Add-Member NoteProperty -name ResourceStatus -value $ResourceStatus

        Return $obj
}
#############################################################################################


write-host "** Azure Resource Naming Convention Best Practice Checker **" -ForegroundColor Magenta

$NamingConventionCacheFile = '.\MS-ResourceNamingConventions_Cache.csv'
$BestPracticeReportPath    = '.\MS-ResourceNamingConventions_Report.csv'

Use-CorpProxy

if(-not (Test-Path $NamingConventionCacheFile)) {

    write-host "No Naming Convention Best Practice Cache found" -ForegroundColor Yellow
    write-host "Creating Naming Convention Best Practice Cache from Microsoft" -ForegroundColor Cyan
    $NamingConventionPSO = Get-MSResourceBestPracticePSO

    if($NamingConventionPSO.Count -gt 100) {
        write-host "Found $($NamingConventionPSO.Count) entries" -ForegroundColor Green
        $NamingConventionPSO | Export-CSV -Path $NamingConventionCacheFile -NoTypeInformation
    } else {
        write-host "Failed to retrieve entries" -ForegroundColor Yellow
        throw "Failed to download best practice naming conventions from Microsoft site"
    }

    #$NamingConventionPSO | ft
} else {
    write-host "Importing existing Naming Convention Best Practice Cache" -ForegroundColor Cyan
    $NamingConventionPSO = Import-CSV -Path $NamingConventionCacheFile

    if($NamingConventionPSO.Count -gt 100) {
        write-host "Found $($NamingConventionPSO.Count) entries" -ForegroundColor Green
        $NamingConventionPSO | Export-CSV -Path $NamingConventionCacheFile -NoTypeInformation
    } else {
        write-host "Failed to retrieve entries" -ForegroundColor Yellow
        throw "Failed to import existing best practice naming conventions from cache file"
    }
    #$NamingConventionPSO | ft
}


# Set to use default proxy creds when making internet calls
#[System.Net.WebRequest]::DefaultWebProxy.Credentials =  [System.Net.CredentialCache]::DefaultCredentials

require-Module 'az' -AlwaysUpdate $true

require-AzConnect

# Get a list of all Subscriptions
$SubscriptionsList = Get-AzSubscription

$Location     = 'uksouth'
$BestPracticeReport = @()

ForEach($Subscription in $SubscriptionsList) {
    write-host "Processing subscription $($Subscription.Name)" -ForegroundColor Cyan
    Set-Subscription $Subscription.Name

    $ResourceGroups = Get-AzResourceGroup -Location $Location
    #$DeploymentTemplatePath = ".\exports\$($Subscription.Name)-$((Get-Date).ToString('yyyy-MM-dd_HH-mm-ss'))"
    #write-host " - Creating Folder for subscription $($Subscription.Name)..." -ForegroundColor Cyan
    #$silent = mkdir $DeploymentTemplatePath -ErrorAction SilentlyContinue

    if(Test-Path $DeploymentTemplatePath) {
        if($ResourceGroups.Count -gt 0) {
            write-host " - Found $($ResourceGroups.Count) Resource Groups in subscription" -ForegroundColor Green
            #$ResourceGroups | Out-File "$DeploymentTemplatePath\ResourceGroups.log"

            ForEach($ResourceGroup in $ResourceGroups) {
                write-host "   - Getting resources for resource group $($ResourceGroup.ResourceGroupName)..." -ForegroundColor Cyan

                #TODO: Since a newer version of AZ module, this can break with missing subscription filter. Suggestion to use -DefaultProfile param with Context
                $Resources = Get-AzResource -ResourceGroupName $ResourceGroup.ResourceGroupName # -ExpandProperties
                
                ForEach($Resource in $Resources) {
                    $Result = Test-MSResourceNamingConvention -ResourceName $Resource.Name -ResourceCode $Resource.Type -NamingConventionPSO $NamingConventionPSO
                    if($Result.ResourceStatus -eq 'Invalid') {
                        write-host "    - $($Resource.Name) in $($ResourceGroup.ResourceGroupName) does not match best practice for $($Result.ResourceType)" -ForegroundColor Red
                        write-host "       ( Expected a prefix of $($Result.ExpectedPrefix) )" -ForegroundColor Red
                    }elseif($Result.ExpectedPrefix -eq 'Unknown') {
                        write-host "    - $($Resource.Name) in $($ResourceGroup.ResourceGroupName) of type $($Result.ResourceType) has no naming convention defined" -ForegroundColor Yellow
                    } else {
                        write-host "    - $($Resource.Name) in $($ResourceGroup.ResourceGroupName) is a valid $($Result.ResourceType)" -ForegroundColor Green
                    }
                    $BestPracticeReport += Add-BestPracticeReportEntry -Subscription $Subscription.Name -ResourceGroup $ResourceGroup.ResourceGroupName `
                                                                       -ResourceName $Resource.Name -ResourceType $Resource.Type -ExpectedPrefix $Result.ExpectedPrefix `
                                                                       -ResourceStatus $Result.ResourceStatus
                }

                #$Resources | Out-File "$DeploymentTemplatePath\Resources.log"
                #write-host "   - Exporting Resource Group $($ResourceGroup.ResourceGroupName)..." -ForegroundColor Cyan
                #$ExportWarning = ''
                #$WarningLogFile = "$DeploymentTemplatePath\$($ResourceGroup.ResourceGroupName)_WARNING.log"
                #$DeploymentTemplate = Export-AzResourceGroup -ResourceGroupName $ResourceGroup.ResourceGroupName -Path $DeploymentTemplatePath -IncludeParameterDefaultValue -IncludeComments -Force
            }
        } else {
            write-host "No Resource Groups Found." -ForegroundColor Yellow
        }
    } else {
        write-host "Unable to create folder $DeploymentTemplatePath!" -ForegroundColor Red
    }
}

if($BestPracticeReport) {
    $BestPracticeReport | Export-CSV -Path $BestPracticeReportPath -NoTypeInformation
}

write-host "Done" -ForegroundColor Green
