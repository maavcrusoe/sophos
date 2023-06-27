# sophos
Automate your alerts from Sophos using APIs

![Automate Sophos alerts](https://github.com/maavcrusoe/sophos/blob/main/sophos.jpg)

## Configure your Script
1. Create Business APP in Azure and set clientID and clientSecret
2. Create Sophos API and set client_id,client_secret,tenantId
3. Create Urlscan API
4. Set email sender and destination address

# Process
1. Script get all events on sophos API, if have more than 200 results compose object with all result
2. Filter alerts with our $exclude_types
3. If alerts have URL send link to urlscan and retreive score points
4. Finally send a email to users
