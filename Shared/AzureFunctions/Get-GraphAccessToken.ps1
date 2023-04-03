# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\ScriptUpdateFunctions\Invoke-WebRequestWithProxyDetection.ps1

function Get-GraphAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$AzureADEndpoint = "https://login.microsoftonline.com",

        [Parameter(Mandatory = $false)]
        [string]$GraphApiUrl = "https://graph.microsoft.com",

        [Parameter(Mandatory = $false)]
        [string]$Scope = "$($GraphApiUrl)//AuditLog.Read.All Directory.AccessAsUser.All email openid profile"
    )

    <#
        This function is used to get an access token for the Azure Graph API by using the OAuth 2.0 authorization code flow
        with PKCE (Proof Key for Code Exchange). The OAuth 2.0 authorization code grant type, or auth code flow,
        enables a client application to obtain authorized access to protected resources like web APIs.
        The auth code flow requires a user-agent that supports redirection from the authorization server
        (the Microsoft identity platform) back to your application.

        More information about the auth code flow with PKCE can be found here:
        https://learn.microsoft.com/azure/active-directory/develop/v2-oauth2-auth-code-flow#protocol-details
    #>

    begin {
        Write-Verbose "Calling $($MyInvocation.MyCommand)"
        function StartLocalListener {
            param(
                [int]$Port = 8004,
                [int]$TimeoutSeconds = 120
            )

            $url = $null
            $authCompletedWording = "Authentication complete. You can return to the application. Feel free to close this browser tab."
            $stopWatch = [system.diagnostics.stopwatch]::StartNew()
            $listener = New-Object "Net.HttpListener"
            $listener.Prefixes.add("http://localhost:$($Port)/")
            try {
                $listener.Start()
                Start-Sleep -Seconds 2
                while (($listener.IsListening) -and
                    ($stopWatch.Elapsed.Seconds -le $TimeoutSeconds)) {
                    $context = $listener.GetContext()
                    $request = $context.Request
                    $response = $context.Response
                    $url = $request.RawUrl
                    $content = [byte[]]@()

                    if ($url.Contains("code=")) {
                        $content = [System.Text.Encoding]::UTF8.GetBytes($authCompletedWording)
                        $response.OutputStream.Write($content, 0, $content.Length)
                        $response.Close()
                        break
                    } else {
                        $response.StatusCode = 404
                        $response.OutputStream.Write($content, 0, $content.Length)
                        $response.Close()
                        break
                    }
                }
            } finally {
                Start-Sleep -Seconds 2
                $listener.Stop()
                $stopWatch.Stop()
            }

            return $url
        }

        function NewS256CodeChallengeVerifier {
            param()

            # https://www.rfc-editor.org/rfc/rfc7636

            $bytes = [System.Byte[]]::new(64)
            [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
            $b64String = [Convert]::ToBase64String($bytes)
            $verifier = $b64String.TrimEnd("=").Replace("+", "-").Replace("/", "_")

            $newMemoryStream = [System.IO.MemoryStream]::new()
            $newStreamWriter = [System.IO.StreamWriter]::new($newMemoryStream)
            $newStreamWriter.write($verifier)
            $newStreamWriter.Flush()
            $newMemoryStream.Position = 0
            $hash = Get-FileHash -InputStream $newMemoryStream | Select-Object Hash
            $hex = $hash.Hash

            $bytesArray = [byte[]]::new($hex.Length / 2)

            for ($i = 0; $i -lt $hex.Length; $i+=2) {
                $bytesArray[$i/2] = [Convert]::ToByte($hex.Substring($i, 2), 16)
            }

            $base64Encoded = [Convert]::ToBase64String($bytesArray)
            $base64UrlEncoded = $base64Encoded.TrimEnd("=").Replace("+", "-").Replace("/", "_")

            return [PSCustomObject]@{
                Verifier      = $verifier
                CodeChallenge = $base64UrlEncoded
            }
        }

        function ConvertJwtFromBase64StringWithoutPadding {
            param(
                [Parameter(Mandatory = $true)]
                [string]$Jwt
            )
            $Jwt = ($Jwt.Replace("-", "+")).Replace("_", "/")
            switch ($Jwt.Length % 4) {
                0 { return [System.Convert]::FromBase64String($Jwt) }
                2 { return [System.Convert]::FromBase64String($Jwt + "==") }
                3 { return [System.Convert]::FromBase64String($Jwt + "=") }
                default { throw "The JWT is not a valid Base64 string." }
            }
        }

        function DecodeJwtToken {
            param(
                [Parameter(Mandatory = $true)]
                [ValidatePattern("^([a-zA-Z0-9_=]+)\.([a-zA-Z0-9_=]+)\.([a-zA-Z0-9_\-\+\/=]*)")]
                [string]$Token
            )

            $tokenParts = $Token.Split(".")
            $tokenHeader = $tokenParts[0]
            $tokenPayload = $tokenParts[1]
            $tokenSignature = $tokenParts[2]

            $tokenHeaderDecoded = [System.Text.Encoding]::UTF8.GetString((ConvertJwtFromBase64StringWithoutPadding $tokenHeader))
            $tokenPayloadDecoded = [System.Text.Encoding]::UTF8.GetString((ConvertJwtFromBase64StringWithoutPadding $tokenPayload))
            $tokenSignatureDecoded = [System.Text.Encoding]::UTF8.GetString((ConvertJwtFromBase64StringWithoutPadding $tokenSignature))

            return [PSCustomObject]@{
                Header    = ($tokenHeaderDecoded | ConvertFrom-Json)
                Payload   = ($tokenPayloadDecoded | ConvertFrom-Json)
                Signature = $tokenSignatureDecoded
            }
        }

        $clientId = "1950a258-227b-4e31-a9cf-717495945fc2" # Well-known Microsoft Azure PowerShell application ID
        $responseType = "code" # Provides the code as a query string parameter on our redirect URI
        $prompt = "select_account" # We want to show the select account dialog
        $redirectUri = "http://localhost:8004" # This is the default port for the local listener
        $codeChallengeMethod = "S256"
        $codeChallengeVerifier = NewS256CodeChallengeVerifier
        $state = ([guid]::NewGuid()).guid
        $connectionSuccessful = $false
    }
    process {
        $codeChallenge = $codeChallengeVerifier.CodeChallenge
        $codeVerifier = $codeChallengeVerifier.Verifier

        # Request an authorization code from the Microsoft Azure Active Directory endpoint
        $authCodeRequestUrl = "$AzureADEndpoint/organizations/oauth2/v2.0/authorize?client_id=$clientId" +
        "&response_type=$responseType&redirect_uri=$redirectUri&scope=$scope&state=$state&prompt=$prompt" +
        "&code_challenge_method=$codeChallengeMethod&code_challenge=$codeChallenge"

        Start-Process -FilePath $authCodeRequestUrl
        $authCodeResponse = StartLocalListener

        if ($null -ne $authCodeResponse) {
            # Redeem the returned code for an access token
            $redeemAuthCodeParams = @{
                Uri             = "$AzureADEndpoint/organizations/oauth2/v2.0/token"
                Method          = "POST"
                ContentType     = "application/x-www-form-urlencoded"
                Body            = @{
                    client_id     = $clientId
                    scope         = $scope
                    code          = ($($authCodeResponse.Split("=")[1]).Split("&")[0])
                    redirect_uri  = $redirectUri
                    grant_type    = "authorization_code"
                    code_verifier = $codeVerifier
                }
                UseBasicParsing = $true
            }
            $redeemAuthCodeResponse = Invoke-WebRequestWithProxyDetection -ParametersObject $redeemAuthCodeParams

            if ($redeemAuthCodeResponse.StatusCode -eq 200) {
                $tokens = $redeemAuthCodeResponse.Content | ConvertFrom-Json
                $connectionSuccessful = $true
            } else {
                Write-Host "Unable to redeem the authorization code for an access token." -ForegroundColor Red
            }
        } else {
            Write-Host "Unable to acquire an authorization code from the Microsoft Azure Active Directory endpoint." -ForegroundColor Red
        }
    }
    end {
        if ($connectionSuccessful) {
            return [PSCustomObject]@{
                AccessToken = $tokens.access_token
                TenantId    = (DecodeJwtToken $tokens.id_token).Payload.tid
            }
        } else {
            exit
        }
    }
}
