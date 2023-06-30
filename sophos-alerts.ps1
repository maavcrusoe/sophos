# MS Graph API
$clientID = "XXXXXX"
$tenantName = "XXXX.onmicrosoft.com"
$clientSecret = "XXXXX"
$ReqTokenBody = @{
    Grant_Type    = "client_credentials"
    Scope         = "https://graph.microsoft.com/.default"
    client_Id     = $clientID
    Client_Secret = $clientSecret
} 
$global:TokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantName/oauth2/v2.0/token" -Method POST -Body $ReqTokenBody

# Sophos API
$client_id = "XXXXXXX"
$client_secret = "XXXXXXX"
$tenantId = "XXXXXXXXX"
$exclude_types="Event::Endpoint::UpdateSuccess,Event::Endpoint::UpdateRebootRequired"  # here you can add exclude objects

# URL Scan API
$urlScanAPI = "XXXXXXX"

# Config
$count = 0
$mailSender = "USER@DOMAIN.com"                   #email alert
$toEmail = "USER1@DOMAIN.com"
$toEmail2 = "USER2@DOMAIN.com"


function sendEmailMSGraph {
    param ($body,$title)
    $urlquery = "https://graph.microsoft.com/v1.0/users/$mailSender/sendMail"
    $headers = @{
        "Content-type"  = "application/json;charset=utf-8"
        "Authorization" = "Bearer $($global:TokenResponse.access_token)"
    }
    #si tiene que estar asi de mal formateado
    $json = @"
    {
        "message": {
            "subject": "$($title)",
            "body": {
              "contentType": "html",
              "content": "$($body)"
            },
            "toRecipients": [
              {
                "emailAddress": {
                  "address": "$($toEmail)"
                }
              },
              {
                "emailAddress": {
                  "address": "$($toEmail2)"
                }
            }

            ]     
          },
          "saveToSentItems": "false"
    }
"@  
    Invoke-RestMethod -Method 'POST' -Uri $urlquery -Body $json -Headers $headers
    write-host "Mail Send!" -ForegroundColor Green
}

function sophosGetToken{
    $contentType = 'application/x-www-form-urlencoded' 
    $authorization = @{
        grant_type = "client_credentials"
        client_id = $client_id
        client_secret = $client_secret
        scope = "token"
    }
    $apiUrl = "https://id.sophos.com/api/v2/oauth2/token"
    $Data = Invoke-RestMethod -ContentType $contentType -Body $authorization -Uri $apiUrl -Method POST 
    if($Data.errorCode -eq "success"){
        return $Data
    }else{
        return $null
    } 
}
function sophosGetSiemAlerts{
    Param($token,$exclude_types,$cursor)   
    $counter = 0
    $Results = @()
    $headers = @{
        Authorization = "Bearer $($token.access_token)"
        'X-Tenant-ID'= $tenantId
    }
    $contentType = 'application/json' 

    if($cursor){
        $cursorUrl = "?cursor=$($cursor)"
    }

    if($exclude_types){
        $apiUrl = "https://api-eu01.central.sophos.com/siem/v1/events?exclude_types=$($exclude_types)"
    }else{
        $apiUrl = "https://api-eu01.central.sophos.com/siem/v1/events"#?exclude_types=$($exclude_types)"
    }
    
    if($cursorUrl){
        $apiUrl = "https://api-eu01.central.sophos.com/siem/v1/events$($cursorUrl)"
    }
    
    $Data = Invoke-RestMethod -ContentType $contentType -Headers $headers -Uri $apiUrl -Method GET
    write-host "Items found: $($Data.items.Count)" -BackgroundColor Blue
    $counter += $Data.items.Count
    $Results += $Data.items
    while ($Data.has_more -eq $true) {
        $apiUrl = "https://api-eu01.central.sophos.com/siem/v1/events?cursor=$($Data.next_cursor)"
        $Data = Invoke-RestMethod -ContentType $contentType -Headers $headers -Uri $apiUrl -Method GET
        write-host "Items found in next cursor: $($Data.items.Count)" -BackgroundColor Blue
        $Results += $Data.items
        $counter += $Data.items.Count
    }
    write-host "Total Items found: $($counter)" -ForegroundColor Blue
    return $Results
}

function ScanUrl-VirusTotal {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Url,
        [Parameter(Mandatory=$true)]
        [string]$ApiKey
    )
    $response = Invoke-RestMethod -Method POST -Uri "https://www.virustotal.com/api/v3/urls" -Headers @{ "x-apikey" = $ApiKey } -Body (@{ "data" = $Url })
    return $response
}

function Scan-UrlScanIO {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Url,
        [Parameter(Mandatory = $true)]
        [string]$ApiKey
    )

    $scanUrl = "https://urlscan.io/api/v1/scan/"
    #$resultUrlTemplate = "https://urlscan.io/result/%SCAN_ID%/"
    $scanWaitSeconds = 30

    try {
        $headers = @{ "API-Key" = $ApiKey; 'Content-Type' = 'application/json' }
        $body = @{ "url" = $Url } | ConvertTo-Json

        $response = Invoke-RestMethod -Method Post -Uri $scanUrl -Headers $headers -Body $body
        $scanId = $response.api

        Write-Host "Scanning website..." -ForegroundColor DarkYellow
        Write-Host "Scan ID: $scanId" -ForegroundColor DarkYellow

        Start-Sleep $scanWaitSeconds

        $resultUrl = $scanId
        $result = Invoke-RestMethod -Method Get -Uri $resultUrl

        Write-Host "Scanning finished" -ForegroundColor DarkYellow

        return @($result, $response.api)
    }
    catch {
        $errorMessage = $_.Exception.Message
        Write-Host "Error: $errorMessage" -ForegroundColor Red
        return 400
    }
}

function checkEvent {
    param($data)
    $Report = [System.Collections.Generic.List[Object]]::new()
    $currentAlert = $false
    $data | ForEach-Object {
        if($_.name -like "*xbox*" -or $_.name -like "*msedge*"){
            #write-host "detected xbox..." -ForegroundColor Red
            
        }else{    
            
            if($_.severity -ne "low"){
                #write-host $_
                write-host "=================$($count)======================="
                write-host "🚨 SEVERITY: $($_.severity)" -BackgroundColor DarkYellow
                Write-Host "WHO: $($_.source)" -ForegroundColor Yellow 
                Write-Host "PC: $($_.location)" -ForegroundColor Yellow
                Write-Host "IP: $($_.source_info.ip)" -ForegroundColor Yellow
                Write-Host "Created: $($_.created_at)" -ForegroundColor Yellow
                write-host "--------------------------------------------"
                Write-Host "DESCRIPTION: $($_.name)"  -ForegroundColor Red
                write-host "--------------------------------------------"

                $currentAlert = [PSCustomObject]@{
                    severity    = "&#x1F6A8; SEVERITY: $($_.severity)"
                    who    = "WHO: $($_.source)"
                    pc    = "PC: $($_.location)"
                    ip    = "IP: $($_.source_info.ip)"
                    date    = "Created: $($_.created_at)"
                    description    = "DESCRIPTION: $($_.name)"
                    urlscanned = ""
                    
                }      
                $Report.Add($currentAlert) 
            }

            if($_.group -eq "WEB"){
                if($Data.items.Count -gt 10){
                    Start-sleep 10
                }
                
                write-host "=================$($count)======================="
                #Write-Host "GROUP: $($_.group)" -ForegroundColor Yellow
                write-host "🌍 website: $($_.severity)" -BackgroundColor DarkBlue
                Write-Host "WHO: $($_.source)" -ForegroundColor Yellow 
                Write-Host "PC: $($_.location)" -ForegroundColor Yellow
                Write-Host "IP: $($_.source_info.ip)" -ForegroundColor Yellow
                Write-Host "Created: $($_.created_at)" -ForegroundColor Yellow
                write-host "--------------------------------------------"
                Write-Host "DESCRIPTION: $($_.name)"  -ForegroundColor Red
                write-host "--------------------------------------------"
                
                #check if url is a real url and save in var 
                if($($_.name)){
                    $pattern = "(?:http:?s\:\/\/)?(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*)"
                    if($_.name -match $pattern){
                        $url = $_.name | Select-String -Pattern $pattern | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
                        write-host $url
                        $url = "" + $url + ""
                        
                        # scan url on scanners
                        $urlscanIO = Scan-UrlScanIO -Url $url -ApiKey $urlScanAPI
                        $urlscanned = $urlscanIO.task.reportURL
                        write-host $urlscanned -BackgroundColor Yellow
                        
                        if($urlscanIO -eq 400 -or $urlscanIO -eq 404){
                            write-host "not scanned"
                        }else{
                            if($urlscanIO.verdicts.overall.score -le 0){
                                write-host "Clean url" -ForegroundColor Green
                                write-host $url -ForegroundColor Green
                            }else{
                                Write-Host "Danger" -ForegroundColor Red
                                Write-Host $url -ForegroundColor Red
                            }
                        }
                    }
                }else{
                    $urlscanned = $null
                }

                $currentAlert = [PSCustomObject]@{
                    severity    = "&#x1F310; website: $($_.severity)"
                    who    = "WHO: $($_.source)"
                    pc    = "PC: $($_.location)"
                    ip    = "IP: $($_.source_info.ip)"
                    date    = "Created: $($_.created_at)"
                    description    = "DESCRIPTION: $($_.name)"
                    urlscan    = "&#xF310; URL: $($urlscanIO)"
                    urlscanned    = "&#x1F6C2; Resultado:  $($urlscanned)"
                }      
                $Report.Add($currentAlert)  
            }
        } 
        $count = $count +=1
    }
    $Report | Out-GridView

    if($Report){
        $msg = "$($siemAlerts.Count) Total alerts in Sophos during last 24hrs, to review $($Report.Count) <br/><br/>"
        foreach($x in $Report){
            $msg += "$($x.severity)<br/>"
            $msg += "$($x.who)<br/>"
            $msg += "$($x.pc)<br/>"
            $msg += "$($x.ip)<br/>"
            $msg += "$($x.date)<br/>"
            $msg += "$($x.description)<br/>"
            $msg += "$($x.urlscan)<br/>"
            $msg += "$($x.urlscanned)<br/><br/>"
        } 
        #format json mail
        $msgFin = $msg.Replace('\','\\')
        $msgFin = $msgFin.Replace('"','')
        sendEmailMSGraph -body $msgFin -title "🚨Alerts found in Sophos: $($Report.Count) "
    }
}

# START
$token = sophosGetToken
write-host "Current Token Bearer: $($token.access_token) expire in $($token.expires_in)" -ForegroundColor Green

#get all alerts
$siemAlerts = sophosGetSiemAlerts -token $token #-exclude_types $exclude_types
checkEvent -data $siemAlerts
