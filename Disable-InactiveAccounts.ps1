##Script written for purposes of auditing LastLoginTime of Users in Microsoft Entra ID
## Requirements:


param(
    [bool] $isGCCHigh,
    [Parameter(Mandatory = $false)]
    $tenantID = $null,
    [Parameter(Mandatory = $true)]
    [ValidateSet("User.Read.All", "User.ReadWrite.All")] #Two values provided in case you only want to view but not edit accounts
    [string]$MGGraphScopes,
    [Parameter(Mandatory = $true)]
    [int] $daysOfInactivityThreshold = 90
)

#Begin Function Section
function Login-MGAccount {
    if ($isGCCHigh) {
        $environment = "UsGov"
    }
    else {
        $environment = "Global"
    }
    if ($null -eq $(Get-MgContext)) {
        if ($tenantID -eq $null) {
            $MGGraphScopes = $MGGraphScopes.Clone() + ", AuditLog.Read.All"
            Connect-MgGraph -Scopes $MGGraphScopes -Environment $environment -NoWelcome
        }
        else {
            $MGGraphScopes = $MGGraphScopes.Clone() + ", AuditLog.Read.All" #Audit log access required in addition to validate set scope. 
            Connect-MgGraph -Scopes $MGGraphScopes -TenantId $tenantID -Environment $environment -NoWelcome
        }
    }
    else {
        (Write-Host -ForegroundColor Green ("Currently signed in as {0} in the Azure environment '{1}'!" -f $(Get-MgContext).Account, $(Get-MGContext).Environment))
    }
    
}
#End Function Section

#Begin Script Main Body
Write-Host -ForegroundColor Green ("##[section] Authentication") #Section header for Azure DevOps log trail

Login-MGAccount #Login function to access O365/Azure

$userExceptions = @( #This block sets exceptions so that specific accounts aren't accidentally disabled
    <# put user IDs here for accounts that need to be exempt from this rule
    "19cbccb2-91cf-4c0a-90d4-16c987bf299c", #Service Account A
    "87b0cf30-475f-4c66-952d-f9f6da3508ad", #Service Account B
    "26bf23dc-257f-49ca-a6f2-20568220393b" #Exempted User A
    #>
)
Write-Host -ForegroundColor Green ("##[section] Inactive User Status Check") #Section header for script main body
$allUsers = Get-MgUser
$allUsers.Foreach{
    $lastSignInDateTime = $_.SignInActivity.LastSignInDateTime
    $inactivityWindow = (Get-date).AddDays(-$daysOfInactivityThreshold)
    if ($lastSignInDateTime -gt $inactivityWindow) {
        if($_.Id -notin $userExceptions){
            Write-Host -ForegroundColor Yellow ("##[warning] Account with user name '{0}' has inactivity window greater than the configured inactivity window ({1} days" -f $_.DisplayName, $daysOfInactivityThreshold)
            if("User.ReadWrite.All" -in $(Get-MgContext).Scopes){ #Only run disable action if appropriate permission scope given
                Write-Host -ForegroundColor Cyan ("##[command] Now disabling inactive account '{0}' ({1})" -f $_.UserPrincipalName, $_.Id)
                Update-MgUser -UserId $_.Id -AccountEnabled $false
            }
            else{
                Write-Host -ForegroundColor Yellow ("##[warning] User '{0}' is within inactivity threshold but permissions not granted to disable. Last sign-in was on {1}" -f $_.DisplayName, $lastSignInDateTime)
            }
        }
        else{
            Write-Host -ForegroundColor Yellow ("##[warning] User account {0} ({1}) is exempted from inactivity actions. Skipping!" -f $_.DisplayName, $_.Id)
        }
    }
    else{
        Write-Host ("User '{0}' last sign-in was on {1}" -f $_.DisplayName, $lastSignInDateTime) 
    }
}

##End Script Main Body

Write-Host -ForegroundColor Green "Done!"