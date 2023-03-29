# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-AzureAccessTokenViaAzAccounts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$AzureEnvironmentName = "AzureCloud",

        [Parameter(Mandatory = $false)]
        [string]$GraphApiUrl = "https://graph.microsoft.com"
    )

    <#
        This function is used to get an access token for the Azure Graph API by using the Az.Accounts module.
    #>

    begin {
        Write-Verbose "Calling $($MyInvocation.MyCommand)"
    }
    process {
        try {
            if ($PSVersionTable.PSVersion -lt 5.1.0.0) {
                Write-Host "Az.Accounts module requires PowerShell version 5.1 or higher. You're running PowerShell $($PSVersionTable.PSVersion)" -ForegroundColor Red
                return
            }

            Import-Module "Az.Accounts" -ErrorAction Stop
            Write-Host "Prompting user for authentication, please minimize this window if you do not see an authorization prompt as it may be in the background"
            [void](Connect-AzAccount -Environment $AzureEnvironmentName -ErrorAction Stop)
            $azContext = Get-AzContext -ErrorAction Stop

            if ($null -ne $azContext) {
                # Parameters for the Authenticate method are:
                # Account, Environment, Tenant, PromptBehavior, TokenCache, Credential, GraphEndpoint
                # https://learn.microsoft.com/dotnet/api/microsoft.azure.commands.common.authentication.factories.authenticationfactory.authenticate
                $azAuth = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate(
                    $azContext.Account,
                    $azContext.Environment,
                    "$($azContext.Tenant.Id)",
                    $null,
                    "Never",
                    $null,
                    $GraphApiUrl
                )
            } else {
                Write-Host "Something went wrong while connecting to Azure AD. Please try again." -ForegroundColor Red
                return
            }
        } catch [System.IO.FileNotFoundException] {
            Write-Host "The Az.Accounts module was not found on this computer. Please install it by running: Install-Module -Name `"Az.Accounts`"" -ForegroundColor Red
            return
        } catch {
            Write-Host "Failed to authenticate with Azure AD. Please check your credentials and try again - Exception:`n$_" -ForegroundColor Red
            return
        }
    }
    end {
        return [PSCustomObject]@{
            AccessToken = $azAuth.AccessToken
            UserId      = $azAuth.UserId
            TenantId    = $azContext.Tenant.Id
        }
    }
}
