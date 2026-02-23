<#
Script Info

Author: Pierre Audonnet [MSFT]
Blog: http://blogs.technet.com/b/pie/
Download: https://gallery.technet.microsoft.com/List-Active-Directory-24d9d346

Disclaimer:
This sample script is not supported under any Microsoft standard support program or service. 
The sample script is provided AS IS without warranty of any kind. Microsoft further disclaims 
all implied warranties including, without limitation, any implied warranties of merchantability 
or of fitness for a particular purpose. The entire risk arising out of the use or performance of 
the sample scripts and documentation remains with you. In no event shall Microsoft, its authors, 
or anyone else involved in the creation, production, or delivery of the scripts be liable for any 
damages whatsoever (including, without limitation, damages for loss of business profits, business 
interruption, loss of business information, or other pecuniary loss) arising out of the use of or 
inability to use the sample scripts or documentation, even if Microsoft has been advised of the 
possibility of such damages
#>
<#
.Synopsis
    This script tries to identify the forest milestone of the environment using metadata and other information.

.DESCRIPTION
    This script collect metadata and other information in order to determine when the infrastructures operations
    such as domain creation or update have been performed in the current forest.

.EXAMPLE
    .\Get-ADHistory.ps1

.EXAMPLE
    To disable the javascript in the report:
    .\Get-ADHistory.ps1 -Javascript $false
 
.INPUTS
    -Javascript [$true|$false]
        Add Javascript to the HTML report. 
    -XmlExport [$true|$false]
        Export the output in an XML format for further use.
    -DebugOutput [$true|$false]
        For test purposes only, print out debug info.

.OUTPUTS
   By default, it generates only an HTML report. If the -XmlExport is set to $true, it will generate an XML output.
.NOTES
    Version Tracking
    10:22 PM 2014-11-24
    Version 1.0
        - First public release
    11:06 AM 2014-11-25
    Version 1.1
        - Add detection for last FFL and DFL change
        - Add detection for trust creation
        - Correct the 2003 Domain prep detection
        - Reduction of the number of call to the _GetMetadata function
        - Add value when possible for object change
    04:31 PM 2014-12-16
    Version 2.0
        - Add support for PowerShell 2.0 (was not working properly prior version 2.0)
        - Add detection for last password change for the krbtgt account
        - Correct the trust detection calls to list all trusts including the internal trusts
        - Add detection for last password change for all the trusts
        - Correct the output for the number of time an attribute changed in the HTML output
        - Correct the output for the lasf FFL value in the HTML output
        - Exclude the Schema version from the HTML output since it might be confusing (it shown the date of the collection)
    09:36 PM 2015-01-08
    Version 2.1
        - Correct version number in the script
        - Add detection for 1st Windows Server 2003 DC
        - Add detection for 1st Windows Server 2003 SP1 DC
        - Add detection for MOM AD replication MP
        - Add detection for SCOM AD replication MP
        - Add detection for Exchange organization creation
    04:26 PM 2015-01-15
    Version 2.2
        - Add the version number in the HTML report
        - Correct the way the time is stored and display to reflect an hour from 0 to 23
        - Correct the detection logic for 2003R2 schema
        - Add legend to the HTML report
    01:29 PM 2017-10-31
    Version 2.3
        - Add detection for 2016 schema
        - Add detection for 2016 functional level
        - Correct detection for first 2008R2 PDC
    03:46 PM 2017-11-15
    Version 2.4
        - Correct detection for 2016 schema (attribute: ms-DS-Key-Id)
	
	02:25 PM 2023-06-09
    Version 2.5
        - Correct detection for 2019 schema (attribute: ms-DS-Preferred-Data-Location)

#>
param(
    [bool]   $Javascript    = $true,
    [bool]   $XmlExport     = $false,
    [bool]   $DebugOutput   = $false
)
$_script_version = "2.4"
#Set the debug output, if set to $true then the Write-Debug will be displayed on the screen
If ( $DebugOutput -eq $true )   { $DebugPreference = "Continue"   } Else { $DebugPreference = "SilentlyContinue"  }
$_format_date = "yyyy-MM-dd HH:mm:ss"
$_script_start_time = (Get-Date).ToString($_format_date)
#The timestamp is used to prefix the HTML ouput report
$_timestamp = (Get-Date).toString(‘yyyyMMddhhmm’)
$_output_report = "$_timestamp-ADHistory.html"
$_output_export = "$_timestamp-ADHistory.xml"
# Set wether or not the report will contain a javascript to hide/show section
$_javascript = $Javascript
Write-Debug "Script start: $_script_start_time"
# Display who and from where the collection is performed
# For stats
$_script_start_collection = Get-Date
$_collection_machine_name = (Get-WmiObject Win32_ComputerSystem).Name
$_collection_machine_domain = (Get-WmiObject Win32_ComputerSystem).Domain
Write-Debug "Collection machine: $_collection_machine_name (domain: $_collection_machine_domain))"
$_collection_user_name   = $([Environment]::UserName)
$_collection_user_domain = $([Environment]::UserDomainName)
Write-Debug "Operator account: $_collection_user_domain\$_collection_user_name"
# Translation table for objectVersion for the schema
$_SchemaPattern = @{
    13 = "Windows 2000 Server"
    30 = "Windows Server 2003"
    31 = "Windows Server 2003 R2"
    44 = "Windows Server 2008"
    47 = "Windows Server 2008 R2"
    56 = "Windows Server 2012"
    69 = "Windows Server 2012 R2"
    87 = "Windows Server 2016"
	88 = "Windows Server 2019-2022"
}
# Translation table for msDS-Behavior-Version
$_FLPattern = @{
    0 = "DS_BEHAVIOR_WIN2000"
    1 = "DS_BEHAVIOR_WIN2003_WITH_MIXED_DOMAINS"
    2 = "DS_BEHAVIOR_WIN2003"
    3 = "DS_BEHAVIOR_WIN2008"
    4 = "DS_BEHAVIOR_WIN2008R2"
    5 = "DS_BEHAVIOR_WIN2012"
    6 = "DS_BEHAVIOR_WIN2012R2"
    7 = "DS_BEHAVIOR_WIN2016"
}
# _AddToHistory builds a custon PSObject with the properties given in inputs and returns it
function __AddToHistory ($__op, $__type, $__target_context, $__milestone, $__time, $__current_value = "", $__current_version = "")
{
    Write-Debug "_AddToHistory called for the type $__type / context $__target_context / milestone $__milestone"
    $__obj = New-Object psobject
    Add-Member -InputObject $__obj -MemberType NoteProperty -Name "Operation" -Value $__op
    Add-Member -InputObject $__obj -MemberType NoteProperty -Name "Type" -Value $__type
    Add-Member -InputObject $__obj -MemberType NoteProperty -Name "Context" -Value $__target_context
    Add-Member -InputObject $__obj -MemberType NoteProperty -Name "Milestone" -Value $__milestone
    Add-Member -InputObject $__obj -MemberType NoteProperty -Name "Time" -Value $__time
    Add-Member -InputObject $__obj -MemberType NoteProperty -Name "Current value" -Value $__current_value
    Add-Member -InputObject $__obj -MemberType NoteProperty -Name "Version" -Value $__current_version
    return $__obj
}
# _GetMetadata function return the following hashtable populated with the metadata of the attribute $__attribute
# of the $__object_dn in the specified domain $__target_domain:
#  - _SourceDSA = LastOriginatingInvocationId
#  - _Version = Version
#  - _TimeChanged = LastOriginatingChangeTime
function _GetMetadata ($__target_domain, $__object_dn, $__attribute)
{
    #Lower the attribute case since it seems to be a problem for PowerShell 2.0
    $__attribute = $__attribute.ToLower()
    #The hashtable used to return results
    $__return = @{ _SourceDSA = "" ; _Version = "" ; _TimeChanged = "" }
    #Init the context and pick a DC
    Try
    {
        Write-Debug "Create an object System.DirectoryServices.ActiveDirectory.DirectoryContext and find a DC for $__target_domain"
        $__meta_context = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain",$__target_domain)
        $__meta_context_loaded = [System.DirectoryServices.ActiveDirectory.DomainController]::findOne($__meta_context)
    }
    Catch
    {
        Write-Debug "Could not get the System.DirectoryServices.ActiveDirectory.DirectoryContext for $__target_domain"
    }
    Try   { $__object_meta = $__meta_context_loaded.GetReplicationMetadata($__object_dn) }
    Catch { Write-Debug "Could not get the GetReplicationMetadata information for $__object_dn" }
    #Store metadata value into the return variable
    Try   { $__return._SourceDSA = $(($__object_meta[$__attribute]).LastOriginatingInvocationId) }
    Catch { $__return._SourceDSA = "N/A" }
    Try   { $__return._Version = $(($__object_meta[$__attribute]).Version) }
    Catch { $__return._Version = "N/A" }
    Try   { $__return._TimeChanged = (Get-Date $( (($__object_meta[$__attribute]).LastOriginatingChangeTime).ToUniversalTime() ) ).ToString($_format_date) }
    Catch { $__return._TimeChanged = "N/A" }
    #Clean objects
    $__meta_context = $__object_meta = $__meta_context_loaded = $null
    #Return the hashtable
    return $__return
}
# _GetWhenCreated function return the value of the whenCreated for the object $__object_dn of the domain $__target_domain
function _GetWhenCreated ($__target_domain, $__object_dn)
{
    Try
    {
        Write-Debug "Getting the whenCreated attribute for LDAP://$__target_domain/$__object_dn"
        $__adsi = [ADSI]"LDAP://$__target_domain/$__object_dn"
        # Update v2.0 Lower the attribute case for whenCreated since it seems to be a problem for PowerShell 2.0
        $__whenCreated = (Get-Date $(($__adsi).whencreated)).ToString($_format_date) #Note that time is already UTC here
    }
    Catch
    {
        $__whenCreated = "N/A"
        Write-Debug "Could not get the whenCreated attribute for LDAP://$__target_domain/$__object_dn"
    }
    return $__whenCreated
}
#Init the array $_history
$_history = @()
#Get the current forest
Try
{
    Write-Debug "Reading the forest's information"
    $_forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
}
Catch
{
    Write-Debug "Cannot get [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()"
    #Throw "Cannot connect to the current forest!"
}
# Initializing the forest variables
$_forest_name = $($_forest.RootDomain.Name)
$_forest_config  = $(([ADSI]"LDAP://RootDSE").configurationNamingContext)
$_forest_schema = $(([ADSI]"LDAP://RootDSE").schemaNamingContext)
$_forest_root = $($_forest.RootDomain.Name)
$_forest_mode = $($_forest.ForestMode)
$_forest_schema_level = $(([ADSI]"LDAP://$_forest_schema").objectVersion)
$_forest_schema_level_version = (_GetMetadata $_forest_root $_forest_schema "objectVersion")._Version
#++ Store the current version of the schema
$_history += __AddToHistory "config" "Config" $_forest_name "Schema version" $_script_start_time $_forest_schema_level $_forest_schema_level_version
$_forest_creation_time = _GetWhenCreated $_forest_root $_forest_schema
#++ Forest creation time
$_history += __AddToHistory "creation" "Forest" $_forest_name "Forest creation" $_forest_creation_time 
# Getting Info About the Schema
# These are attributes brought by the corresponding schema extension
# Note there are other way to get those information, this is just one of them
#++ Schema 2000
$_schema_2000   = (_GetMetadata $_forest_root "CN=Account-Expires,$_forest_schema" "whenCreated")._TimeChanged
$_history += __AddToHistory "schema" "Forest" $_forest_name "Schema 2000" $_schema_2000
#++ Schema 2003
$_schema_2003   = (_GetMetadata $_forest_root "CN=ms-PKI-Cert-Template-OID,$_forest_schema" "whenCreated")._TimeChanged
$_history += __AddToHistory "schema" "Forest" $_forest_name "Schema 2003" $_schema_2003
#++ Schema 2003R2
$_schema_2003R2 = (_GetMetadata $_forest_root "CN=ms-DFSR-Enabled,$_forest_schema" "whenCreated")._TimeChanged
$_history += __AddToHistory "schema" "Forest" $_forest_name "Schema 2003R2" $_schema_2003R2
#++ Schema 2008
$_schema_2008   = (_GetMetadata $_forest_root "CN=ms-DS-PSO-Applied,$_forest_schema" "whenCreated")._TimeChanged
$_history += __AddToHistory "schema" "Forest" $_forest_name "Schema 2008" $_schema_2008
#++ Schema 2008R2
$_schema_2008R2 = (_GetMetadata $_forest_root "CN=ms-DS-Managed-Service-Account,$_forest_schema" "whenCreated")._TimeChanged
$_history += __AddToHistory "schema" "Forest" $_forest_name "Schema 2008R2" $_schema_2008R2
#++ Schema 2012
$_schema_2012   = (_GetMetadata $_forest_root "CN=ms-DS-RID-Pool-Allocation-Enabled,$_forest_schema" "whenCreated")._TimeChanged
$_history += __AddToHistory "schema" "Forest" $_forest_name "Schema 2012" $_schema_2012
#++ Schema 2012R2
$_schema_2012R2 = (_GetMetadata $_forest_root "CN=ms-DS-AuthN-policy-Silos,$_forest_schema" "whenCreated")._TimeChanged
$_history += __AddToHistory "schema" "Forest" $_forest_name "Schema 2012R2" $_schema_2012R2
#++ Schema 2016
$_schema_2016 = (_GetMetadata $_forest_root "CN=ms-DS-Key-Id,$_forest_schema" "whenCreated")._TimeChanged
$_history += __AddToHistory "schema" "Forest" $_forest_name "Schema 2016" $_schema_2016
#++ Schema 2019
$_schema_2019 = (_GetMetadata $_forest_root "CN=ms-DS-Preferred-Data-Location,$_forest_schema" "whenCreated")._TimeChanged
$_history += __AddToHistory "schema" "Forest" $_forest_name "Schema 2019" $_schema_2019
# Creation of an Exchange org
$_forest_exchange_org_dn = "CN=Microsoft Exchange,CN=Services,$_forest_config"
$_forest_exchange_org_time = _GetWhenCreated $_forest_root $_forest_exchange_org_dn
$_history += __AddToHistory "infra" "Forest" $_forest_name "Creation Exchange Org" $_forest_exchange_org_time
#Adding important forest change
#dSHeursitics
$_forest_dSHeuristics_dn       = "CN=Directory Service,CN=Windows NT,CN=Services,$_forest_config"
$_forest_dSHeuristics_value    = ([ADSI]"LDAP://$_forest_dSHeuristics_dn").Properties.dSHeursitics
$_forest_dSHeuristics_metadata = _GetMetadata $_forest_root $_forest_dSHeuristics_dn "dSHeursitics"
$_forest_dSHeuristics_changed  = $_forest_dSHeuristics_metadata._TimeChanged
$_forest_dSHeuristics_version  = $_forest_dSHeuristics_metadata._Version
$_history += __AddToHistory "config" "Forest" $_forest_name "dSHeursitics last change to $_forest_dSHeuristics_value" $_forest_dSHeuristics_changed $_forest_dSHeuristics_value $_forest_dSHeuristics_version
#tombstoneLifeTime
$_forest_tombstoneLifeTime_dn      = "CN=Directory Service,CN=Windows NT,CN=Services,$_forest_config"
$_forest_tombstoneLifeTime_value   = [string] ([ADSI]"LDAP://$_forest_tombstoneLifeTime_dn").Properties.tombstoneLifeTime
#If the value is not set, we store 60 days
If ( $_forest_tombstoneLifeTime_value -eq $null -or $_forest_tombstoneLifeTime_value -eq "" )
{
    $_forest_tombstoneLifeTime_value = "60*"
}
$_forest_tombstoneLifeTime_metadata = _GetMetadata $_forest_root $_forest_tombstoneLifeTime_dn "tombstoneLifeTime"
$_forest_tombstoneLifeTime_changed  = $_forest_tombstoneLifeTime_metadata._TimeChanged
$_forest_tombstoneLifeTime_version  = $_forest_tombstoneLifeTime_metadata._Version
$_history += __AddToHistory "config" "Forest" $_forest_name "tombstoneLifeTime last change to $_forest_tombstoneLifeTime_value" $_forest_tombstoneLifeTime_changed $_forest_tombstoneLifeTime_value $_forest_tombstoneLifeTime_version
#DefaultLDAPPolicy 
$_forest_lDAPAdminLimits_dn       = "CN=Default Query Policy,CN=Query-Policies,CN=Directory Service,CN=Windows NT,CN=Services,$_forest_config"
$_forest_lDAPAdminLimits_value    = [string] ([ADSI]"LDAP://$_forest_lDAPAdminLimits_dn").Properties.lDAPAdminLimits
$_forest_lDAPAdminLimits_metadata = _GetMetadata $_forest_root $_forest_lDAPAdminLimits_dn "lDAPAdminLimits"
$_forest_lDAPAdminLimits_changed  = $_forest_lDAPAdminLimits_metadata._TimeChanged
$_forest_lDAPAdminLimits_version  = $_forest_lDAPAdminLimits_metadata._Version
$_history += __AddToHistory "config" "Forest" $_forest_name "lDAPAdminLimits last change" $_forest_lDAPAdminLimits_changed $_forest_lDAPAdminLimits_value $_forest_lDAPAdminLimits_version
#option for IP replication
$_forest_options_dn      = "CN=IP,CN=Inter-Site Transports,CN=Sites,$_forest_config"
$_forest_options_value   = [string] ([ADSI]"LDAP://$_forest_options_dn").Properties.options
$_forest_options_metadata = _GetMetadata $_forest_root $_forest_options_dn "options"
$_forest_options_changed = $_forest_options_metadata._TimeChanged
$_forest_options_version = $_forest_options_metadata._Version
$_history += __AddToHistory "config" "Forest" $_forest_name "IP Sites options last change" $_forest_options_changed $_forest_options_value $_forest_options_version
#RODC Prep
$_forest_rodcprep_dn = "CN=ActiveDirectoryRodcUpdate,CN=ForestUpdates,$_forest_config"
$_forest_rodcprep_time = _GetWhenCreated $_forest_root $_forest_rodcprep_dn
$_history += __AddToHistory "infra" "Forest" $_forest_name "RODC Prep" $_forest_rodcprep_time
#Last FFL change
$_forest_lastffl_dn = "CN=Partitions,$_forest_config"
$_forest_lastffl_metadata = _GetMetadata $_forest_root $_forest_lastffl_dn "msDS-Behavior-Version"
$_forest_lastffl_time = $_forest_lastffl_metadata._TimeChanged
$_forest_lastffl_version = $_forest_lastffl_metadata._Version
$_forest_lastffl_value = [string] ([ADSI]"LDAP://$_forest_lastffl_dn").Properties."msds-behavior-version"
$_history += __AddToHistory "forestup" "Forest" $_forest_name "Last FFL change (now: $($_FLPattern[[int] $_forest_lastffl_value]))" $_forest_lastffl_time $_forest_lastffl_value $_forest_lastffl_version
#Recycle bin
#This is more complex since it is a linked value
$_forest_rc_searcher_base = "LDAP://CN=Partitions,$_forest_config"
$_forest_rc_searcher_scope = "Base"
$_forest_rc_searcher_properties = "msDS-ReplValueMetaData","msDS-EnabledFeature"
$_forest_rc_searcher_filter = "(objectClass=*)"
$_forest_rc_searcher = New-Object System.DirectoryServices.DirectorySearcher( $_forest_rc_searcher_base , $_forest_rc_searcher_filter , $_forest_rc_searcher_properties , $_forest_rc_searcher_scope )
$_forest_rc_searcher_result = $_forest_rc_searcher.FindOne()
$_forest_rc_searcher_result.Properties."msds-replvaluemetadata" | ForEach-Object `
{
    $_forest_rc_item = [XML] $_
    #Time: $_forest_rc_item.DS_REPL_VALUE_META_DATA.ftimeCreated
    if ( $_forest_rc_item.DS_REPL_VALUE_META_DATA.pszAttributeName -eq "msDS-EnabledFeature" -and $_forest_rc_item.DS_REPL_VALUE_META_DATA.pszObjectDn -eq "CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,$_forest_config" )
    {
        $_forest_rc_time = (Get-Date $_forest_rc_item.DS_REPL_VALUE_META_DATA.ftimeCreated).ToUniversalTime().ToString($_format_date)
        $_history += __AddToHistory "config" "Forest" $_forest_name "Recycle Bin" $_forest_rc_time
    }
}
# TEST -- THIS NEEDS TO BE VERIFIED
#PDC 2003
$_forest_2003_pdc_dn = "CN=NTLM Authentication,CN=WellKnown Security Principals,$_forest_config"
$_forest_2003_pdc_time = _GetWhenCreated $_forest_root $_forest_2003_pdc_dn
$_history += __AddToHistory "infra" "Forest" $_forest_name "First 2003 PDC" $_forest_2003_pdc_time
# TEST -- THIS NEEDS TO BE VERIFIED
#PDC 2008r2
$_forest_2008r2_pdc_dn = "CN=Console Logon,CN=WellKnown Security Principals,$_forest_config"
$_forest_2008r2_pdc_time = _GetWhenCreated $_forest_root $_forest_2008r2_pdc_dn
$_history += __AddToHistory "infra" "Forest" $_forest_name "First 2008R2 PDC" $_forest_2008r2_pdc_time
#Looking at each domain
Write-Debug "Starting the domain section..."
$_forest.Domains | ForEach-Object `
{
    #Looking for the crossRef object
    $_current_domain = $($_.Name)
    Try
    {
        Write-Debug "Getting info for the domain $_current_domain"
        $_searcher_base = "LDAP://CN=Partitions,$_forest_config"
        $_searcher_scope = "Onelevel"
        $_searcher_properties = "distinguishedName","nCName","nTMixedDomain"
        $_searcher_filter = "(&(dnsRoot=$_current_domain)(systemFlags=3))"
        Write-Debug "Calling an object System.DirectoryServices.DirectorySearcher for $_searcher_base"
        $_searcher = New-Object System.DirectoryServices.DirectorySearcher( $_searcher_base , $_searcher_filter , $_searcher_properties , $_searcher_scope )
    }
    Catch
    {
        Write-Debug "Cannot get the domain information for $_current_domain"
    }
    $_searcher_result = $_searcher.FindOne()
    Write-Debug "Xref: $_current_domain_crossref_dn"
    $_current_domain_crossref_dn = $($_searcher_result.Properties.distinguishedname)
    $_current_domain_creation = _GetWhenCreated $_forest_root $_current_domain_crossref_dn
    $_current_domain_dn = $($_searcher_result.Properties.ncname)
    #Adding domain's birth
    $_history += __AddToHistory "creation" "Domain" $_current_domain "Creation" $_current_domain_creation
    #Last DFL change
    $_current_domain_dfl = _GetMetadata $_current_domain $_current_domain_crossref_dn "msDS-Behavior-Version"
    $_current_domain_dfl_time = $_current_domain_dfl._TimeChanged
    $_current_domain_dfl_version = $_current_domain_dfl._Version
    $_current_domain_dfl_value = [string] ([ADSI]"LDAP://$_current_domain_crossref_dn").Properties."msds-behavior-version"
    $_history += __AddToHistory "domainup" "Domain" $_current_domain "Last DFL change (to $($_FLPattern[[int] $_current_domain_dfl_value]))" $_current_domain_dfl_time $_current_domain_dfl_value $_current_domain_dfl_version
    #DFL 2000
    # TEST -- THIS NEEDS TO BE VERIFIED
    # Sometime return a very weird time...
    $_current_domain_2000_dfl_time = (_GetMetadata $_current_domain $_current_domain_crossref_dn "nTMixedDomain")._TimeChanged
    $_history += __AddToHistory "domainup" "Domain" $_current_domain "Native 2000 DFL" $_current_domain_2000_dfl_time
    #2003 domain prep
    $_current_domain_2003_prep_dn = "CN=WMIPolicy,CN=System,$_current_domain_dn"
    $_current_domain_2003_prep_time = _GetWhenCreated $_current_domain $_current_domain_2003_prep_dn
    $_history += __AddToHistory "domainup" "Domain" $_current_domain "Domain prep 2003" $_current_domain_2003_prep_time
    # TEST -- THIS NEEDS TO BE VERIFIED
    # Check is it only DC?
    #2003 first PDC
    $_current_domain_2003_rtm_dn = "<SID=S-1-5-32-560>" #Windows Authorization Access Group
    $_current_domain_2003_rtm_time = _GetWhenCreated $_current_domain $_current_domain_2003_rtm_dn
    $_history += __AddToHistory "infra" "Domain" $_current_domain "First Windows Server 2003 DC" $_current_domain_2003_rtm_time
    # TEST -- THIS NEEDS TO BE VERIFIED
    # Check is it only PDC?
    #2003 SP1 first DC
    $_current_domain_2003_sp1_dn = "<SID=S-1-5-32-562>" #Distributed COM Users
    $_current_domain_2003_sp1_time = _GetWhenCreated $_current_domain $_current_domain_2003_sp1_dn
    $_history += __AddToHistory "infra" "Domain" $_current_domain "First Windows Server 2003 SP1 DC" $_current_domain_2003_sp1_time
    # TEST -- THIS NEEDS TO BE VERIFIED
    #2008 domain prep 
    #Check if ADmin rights are required to list this container
    $_current_domain_2008_prep_dn = "CN=Password Settings Container,CN=System,$_current_domain_dn"
    $_current_domain_2008_prep_time = _GetWhenCreated $_current_domain $_current_domain_2008_prep_dn
    $_history += __AddToHistory "domainup" "Domain" $_current_domain "Domain prep 2008" $_current_domain_2008_prep_time
    #2008R2 domain prep
    $_current_domain_2008r2_prep_dn = "CN=Managed Service Accounts,$_current_domain_dn"
    $_current_domain_2008r2_prep_time = _GetWhenCreated $_current_domain $_current_domain_2008r2_prep_dn
    $_history += __AddToHistory "domainup" "Domain" $_current_domain "Domain prep 2008R2" $_current_domain_2008r2_prep_time
    #2012 domain prep
    $_current_domain_2012_prep_dn = "CN=TPM Devices,$_current_domain_dn"
    $_current_domain_2012_prep_time = _GetWhenCreated $_current_domain $_current_domain_2012_prep_dn
    $_history += __AddToHistory "domainup" "Domain" $_current_domain "Domain prep 2012" $_current_domain_2012_prep_time
    #2012R2 domain prep
    #This one is a little bit tricky, since it is the combination of two modifications that helps to catch the time
    $_current_domain_2012r2_prep_dn = "CN=ActiveDirectoryUpdate,CN=DomainUpdates,CN=System,$_current_domain_dn"
    If ( $(([ADSI]"LDAP://$_current_domain/$_current_domain_2012r2_prep_dn").revision) -eq 10 )
    {
        $_current_domain_2012r2_prep_time = (_GetMetadata $_current_domain $_current_domain_2012r2_prep_dn "revision")._TimeChanged
        $_history += __AddToHistory "domainup" "Domain" $_current_domain "Domain prep 2012R2" $_current_domain_2012r2_prep_time
        #Note that if the DFL is higher than 2012 R2 (for example 2016, the DFL will not be catpure because it does not modify anything
    }
    #20016 domain prep
    $_current_domain_2016_prep_dn = "CN=Keys,$_current_domain_dn"
    $_current_domain_2016_prep_time = _GetWhenCreated $_current_domain $_current_domain_2016_prep_dn
    $_history += __AddToHistory "domainup" "Domain" $_current_domain "Domain prep 2016" $_current_domain_2016_prep_time
    #Adding some more security info
    Write-Debug "Building an ADSI object for the domain to get the objectSid"
    $_domain = [ADSI]"LDAP://$_current_domain"
    $_domain_sid = (New-Object Security.Principal.Securityidentifier($_domain.objectSid[0],0)).Value # Get the SID to a S-x-Y... format
    #Adding when the builtin password changed its password for the last time
    $_current_domain_admin500 = [ADSI] "LDAP://$_current_domain/<SID=$_domain_sid-500>"
    $_current_domain_admin500_dn = [string] $_current_domain_admin500.Properties.distinguishedName
    $_current_domain_admin500_metadata = _GetMetadata $_current_domain $_current_domain_admin500_dn "unicodePwd"
    $_current_domain_admin500_time = $_current_domain_admin500_metadata._TimeChanged
    $_current_domain_admin500_version = $_current_domain_admin500_metadata._Version
    $_history += __AddToHistory "config" "Domain" $_current_domain "Builtin admin password last change (changed $_current_domain_admin500_version times)" $_current_domain_admin500_time "" $_current_domain_admin500_version
    #Adding when the krbtgt password changed its password for the last time
    $_current_domain_krbtgt = [ADSI] "LDAP://$_current_domain/<SID=$_domain_sid-502>"
    $_current_domain_krbtgt_dn = [string] $_current_domain_krbtgt.Properties.distinguishedName
    $_current_domain_krbtgt_metadata = _GetMetadata $_current_domain $_current_domain_krbtgt_dn "unicodePwd"
    $_current_domain_krbtgt_time = $_current_domain_krbtgt_metadata._TimeChanged
    $_current_domain_krbtgt_version = $_current_domain_krbtgt_metadata._Version
    $_history += __AddToHistory "config" "Domain" $_current_domain "KrbTgt password last change (current version $_current_domain_krbtgt_version)" $_current_domain_krbtgt_time "" $_current_domain_krbtgt_version
    #Adding when the pwdProperties changed for the last time
    $_current_domain_pwdProperties_dn = "$_current_domain_dn"
    $_current_domain_pwdProperties_value = [string] ([ADSI]"LDAP://$_current_domain_dn").Properties.pwdProperties
    $_current_domain_pwdProperties_metadata = _GetMetadata $_current_domain $_current_domain_pwdProperties_dn "pwdProperties"
    $_current_domain_pwdProperties_time = $_current_domain_pwdProperties_metadata._TimeChanged
    $_current_domain_pwdProperties_version = $_current_domain_pwdProperties_metadata._Version
    $_history += __AddToHistory "config" "Domain" $_current_domain "pwdProperties last change to $_current_domain_pwdProperties_value" $_current_domain_pwdProperties_time $_current_domain_pwdProperties_value $_current_domain_pwdProperties_version
    # MOM Replication MP
    # It is actually present before MOM 2005, so just display MOM AD MP
    $_current_domain_mom2005_dn = "CN=MomLatencyMonitors,$_current_domain_dn"
    $_current_domain_mom2005_time = _GetWhenCreated $_current_domain $_current_domain_mom2005_dn
    $_history += __AddToHistory "infra" "Domain" $_current_domain "MOM AD MP" $_current_domain_mom2005_time
    # MOM Replication MP
    $_current_domain_scom2007_dn = "CN=OpsMgrLatencyMonitors,$_current_domain_dn"
    $_current_domain_scom2007_time = _GetWhenCreated $_current_domain $_current_domain_scom2007_dn
    $_history += __AddToHistory "infra" "Domain" $_current_domain "SCOM AD MP" $_current_domain_scom2007_time
    #Looking for all trusts
    Write-Debug "Getting external trust for the domain $_current_domain"
    $_trust_searcher_base = "LDAP://CN=system,$_current_domain_dn"
    $_trust_searcher_scope = "Onelevel"
    $_trust_searcher_properties = "distinguishedName","name","flatName"
    $_trust_searcher_filter = "(objectCategory=trustedDomain)"
    Write-Debug "Calling an object System.DirectoryServices.DirectorySearcher for $_trust_searcher_base"
    $_trust_searcher = New-Object System.DirectoryServices.DirectorySearcher( $_trust_searcher_base , $_trust_searcher_filter , $_trust_searcher_properties , $_trust_searcher_scope )
    $_trust_results = $_trust_searcher.FindAll()
    If ($_trust_results.Count -ge 1)
    {
        Write-Debug "$($_trust_results.Count) external trusts found."
        $_trust_results | ForEach-Object `
        {
            $_trust_dn = $($_.Properties.distinguishedname)
            $_trust_name = $($_.Properties.name)
            $_trust_flatname = $($_.Properties.flatname)
            $_trust_creation_time = _GetWhenCreated $_current_domain $_trust_dn
            # get the last password change
            Try {
                $_trust_sAMAccountName = $_trust_flatname+'$'
                $_trust_object = [ADSI]"LDAP://CN=$_trust_sAMAccountName,CN=Users,$_current_domain_dn"
                $_trust_pwdlastset = (([datetime]::FromFileTime( $_trust_object.ConvertLargeIntegerToInt64( $_trust_object.Properties.pwdlastset.value ))).ToUniversalTime()).ToString($_format_date)
                # Add an entry for the last password change in the history 
                $_history += __AddToHistory "infra" "Domain" $_current_domain "<-> $_trust_flatname last password change" $_trust_pwdlastset $_trust_name
            }
            Catch
            {
                $_trust_pwdlastset = "N/A"
                Write-Debug "Cannot determine the last password change for the trust $_trust_flatname"
            }
            $_history += __AddToHistory "infra" "Domain" $_current_domain "External trust created with $_trust_flatname" $_trust_creation_time $_trust_name
        }
    } Else {
        Write-Debug "No external trust found."
    }
}
#$_history | Out-GridView
#Calculate how long the colelction took
$_script_end_collection = ((Get-Date) - $_script_start_collection).Seconds
Write-Debug "Collection time: $_script_end_collection seconds"
If ( $XmlExport -eq $true )
{
    $_history | Export-Clixml $_output_export
}
#base64 embedded images
$_ht_img = @{}
$_ht_img["forest"]     = "<img src=""data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABYAAAAZCAYAAAA14t7uAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAADrSURBVEhL7ZVBCsIwEEV7FS/gUhAP6c6FegPBpRs3giBeQEGliHoAabVWaszoD1QnNE0txpV9MGTSTl5DGRJPCEG/CE9KSS6ARxPjYa29+jo4+IhTMc8r8Su3ips9n8b+iRIh1Yi5qQ7BPcAqnu4iVZQyP1yMdQhOYVdEyV0VpmDnpjoEp1Bcdsc8t4pbfZ8m27MqxIi5qQ4BeG4VlwnuAUZxvbOhwSKg8Kr/42MsaLgMqNHN7hzw3CgerUP1Mo/ZPsqsATw3iuOb/cR7NkdmDSe3Kz7BtqY63bT8z8UpzrtCu6VhdwE8b7GgB+EAjr6jfR4GAAAAAElFTkSuQmCC"" />"
$_ht_img["domain"]     = "<img src=""data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABMAAAAUCAIAAADgN5EjAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAD3SURBVDhP1ZOhDoMwEIbbheAwBDEJAkNQOAQvgOVpeAIeY0/AUyBwBIVBgOQRCCFhV+7oWDcx2Mw+0fz/XS9trlc+jqOmaZxz9sw8z7BCCq1kWRZMicqyLIuiwIQkTVNYsyxDK4miKAxDEBf0J1Ar4zi+rtxWUEOQ0jvEbbuua9sW/TRNeZ6jliRJous6atd1HccBIRowDENd12uceZ6HQkFuMAzjUbknCALTNMls2LbdNA2ZDbWyqqq3tyW143e9/Zz/qhS9hceFV0Lf9z0KBTlGMFIoxJmWZfkbGH2F0r4PmzFy/rZibkke5Isz4Y+TPMjZMxm7A32GTQOptCUXAAAAAElFTkSuQmCC"" />"
$_ht_img["list"]       = "<img src=""data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABMAAAATCAYAAAByUDbMAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsIAAA7CARUoSoAAAAC1SURBVDhP7ZSxCsMgFEVvS7eAP+Ag2cwUyHe4+Z1uzpkyStaQKTjkEwJOpu1D2lCaoa1DoT2DHu7weHLBQwhhRSaO6c4CbWathTEmRa+htYZSijz/ZtM0YRgGCoQQ8N6Tb9nLq6pCWZbkp+sxzzOccxTEGNH3PfmWvZwxdhuW9Zk/Moza7LoObdtS0DQNlmUh37LXZl3XkFKSU5uPjOOY7E5RFE9zznmyf5vv8MX/2Xoh+YcAZ6uBS5QbRMFoAAAAAElFTkSuQmCC"" />"
$_ht_img["config"]     = "<img src=""data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABMAAAATCAIAAAD9MqGbAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAFcSURBVDhPlZI/S4JRFMYfq0EQamgogqy2CorGhsCag9asSce+QVs4WZ+gsVqqMYIgpxqKbFIIpBqkgv4YFBYJBoE9h3u4+mr3Sj/k5ZzrfXjOueeg5ub5SwNL40kHHFR/MLeLclVTwpPkkcbEqcw+4foNqXNNKVvJ4LiIl4qehOirYRBeHdmUe8M98su/iv9UH3JJveBUktMH8aGzYXoAW/MY7dXUpyR3H+JsqK1qYHD2mS+JZ/ZR01b+8Fy/wMZl4FUNTZ4B5cGtPCbdDGxpcQypM03XZuQb7kRiEv0RhJB29smrN+/YL2hqSUzIUzn7JJkiYoMaN8JRb195layWnq1wTjt+JUcy1K2xJdwlpZ4se5VcnftPjS3cLVNIG8+mPlk/DdMxiQNT4TzK39IG17VUkVJpu3So/xri49hbkOAf28feOEa7t75qCd/DMhuty0gbJU04d2K+dYBfjGC4sJtZJeIAAAAASUVORK5CYII=""/>"
$_ht_img["creation"]   = "<img src=""data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABMAAAATCAIAAAD9MqGbAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAHsSURBVDhPlZJNKOVRGMZfRrkh1OQjU0hNSWlYKIspysKUha0dO2PH0mpYsZuszG4s2bllQY0QYTENmpq5PmIo01BjUHJldPyezule11c8nf7/c95znvd9n+ecNOec3YfjuOVHwvwmfp1Yfqa20kPgDnrnwsRj9cA+rehLxj9nityuycbqoU4UZyt9/SurKbTYkcX/W2OpvpGMcDLUjP31f7VRX6Lt6Ja+0OJXSgQNjHwX2UNMcg991YJ+GOB9rb0psJoiJRr9YR3VCtLO1E44INDtTfw7dx/mw5zJ+aUb/qZ59xfXFnVL+25g0XVMuJldd1sn6iMvbHLb2qpscEllK19aeZ76Gt+w3VN1PtysYIq3bHdNySH46CnOUQQaDUPorrO8TPvYJBpI1vRqy3Jt/chaX2uJQ/DfVdjyvloAZMRzErGVhhKMpSsP3KOIr0NNmAwM4+jyb6nAZG94Brlh4iFRHgcpuZWkgSaOL07lvrchCFIcouDYT8lAlQcZuYyGUls7VLwoS2o9kkzq9C+El/UQUNFeHSoHb2f3LLppnbV+JdAzkvxIgPnFlSwA4Q31TNvnFq0T4MXSJIMJOhMYaLCxmOSoW397dNK3oIYfAc+QAijHW9XET2hPB7ZBSXlDz0IKkxf7OJKCza4Bc6z3pDLJvvcAAAAASUVORK5CYII=""/>"
$_ht_img["domainup"]   = "<img src=""data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABMAAAATCAIAAAD9MqGbAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAEmSURBVDhPY/z//z8DKjjwiMFxGZQNAfO9GRJ0oWw4YILSpIMhr1OAncFBDoSmuzN4KIEYEtxQKWSACNsbbxlefIUwQQCooeEIQ4EJw413DD/+QAWBhhqIQ9kInYlbGRZchjAZ2u0ZfvxlaDwCsjPdgCFwHVQcaNz+KCgbi2uBUafAD9IGBDvuMRx8zNDvDJZABeg6gabG6zIkboNygWDCaRCZYQjmIAEUnUCrgMYD3Qb3GAQU7mVwVwQZigwQOgU4GNYHMURuYvjwAyqCDICuaHcAGQ0HiBACagBqA3oMFwBqOx6HiCHG+sMgnUBvcDAzXHgFErrwEuQ8ZFBhCXItEAA1A3UCfQ4MeUaGdpS8AvRMvQ2WvHLwESLOIABLrBAJhpJOBgYA8rBWe0jxcO0AAAAASUVORK5CYII=""/>"
$_ht_img["forestup"]   = "<img src=""data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABMAAAATCAIAAAD9MqGbAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAFVSURBVDhPY/z//z8DNnDhJcOLrwweSlAuJsCpM3Adw4OPDOcToVxMwASlUQHQwg23oCQugF1n41F0BibAohPZKjzWYtGJZg8ua9FD6MMPhguvoGw40BBmkOCGsuEAXWfhXoYJp0GMBF0GeX6GxiMgdoAaw/ogEAMZoLgWGIEzzoMYQEvSDRkMxBgc5EBcSDijARSdnScYfvxh4GBhWO7HkLiVIXEbQ7sD1J2YvkXohFs43Z1h4hmGG29Bfq48wLDcHySIaS1CJ8RCoPcE2BkWXIYKHngEQvU2IDaateghBLRZczbINmSwPwrqYWQAtRMYpJw9oIQKdDAwYIBehQOgnpkXQCYqTgclZjgA6YT4EOhIYKgcfMTQ74wSe0B/vvjCELkRxEb2LUgnxIdA/RBfffgJkYICoBREHOgiIID7lgkepEQCuLVMEAtJAhBrceZsAoCBAQDLQZyT6A7xjQAAAABJRU5ErkJggg==""/>"
$_ht_img["infra"]      = "<img src=""data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABMAAAATCAIAAAD9MqGbAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAGASURBVDhPY/z//z8DEnjxlSFzJ8OHH1AuBAhwMLTbM2gIQ7lQANSJDOZf+r//IZQNB/c//K8/DGXDARPUANIB+TrR/XnhJUPjUQZ9MSgXAl5+BYlkGEK5EIBF58wLDDfeQrkQIMHDkG7A4CAH5UIAis4d9xgC1zH8+APlooH53gwJulA2EKDo9FyFog1oM1pMrA8CxRAUAHXiAglboAysAGHng48MG24xfPgJYguwM3CwgJJEgSmDvSzDhVcgQQ5mhgA1JFdADKg4AELPv0B4IHD86X+Hpf+XX4VygeD99//Tz/0PWAvlQnVaLITQKKD9GJSBDCI2Qi1gBLJefAG5x0AM5MLtYSCHNBxhOPgIGkIK/KBQBYLErSAfAQWBIkBxRoZ2lPj8XwEiFaeDFMEBVkFqpFtgRKHnIxyCQE8BBVmArApLBnZmkNDK6yASAoDxwc8OYuASRHEt1nSHKzEycnT/h8sBnfG9BMQwnA9K+hAAdPD7AhBDczYiJwhwMAAAAwNE8nmP2e8AAAAASUVORK5CYII=""/>"
$_ht_img["schema"]     = "<img src=""data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABMAAAATCAIAAAD9MqGbAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAFxSURBVDhPY/z//z8DNtBwhKHxCEOCLsN8bxB3wy2GC6/AEjDAcuARiJLgZtAQBguAwYWXDAfB4kDVQAUOcgwbbzMsuAyWgwEmx2UMQNR5AsqHAANxBgV+EANoooUUWAgDMEFpDAB0ZL8zw/ogBg4WqAgaYGRoB/kT7h8gADq1cC+UDQHlFiAnvPgK5UIAS70NiDIQA/PA4MNPkN+QQbwug4cSKCCAhgJlgYoFOBiYgCEBRBPPgHwLRGi2oQGgLFANJJChYYsM/FWhDDSQuBXqlsB1DPsjYf6EA2AE7I+CsjEBUPOG2yBtwMDHGbZYATAUzyeCtAEB4/6HIDuB8QYM/QcfQUJwAIzJE8+gbAgQYAeFDUQZIlbk+UHJDRncz2RQnA5lQwDQL/ZyUGWkuRYZkK+Tsf4wyLWQyEWLoQIThglnoGwIAKYkIIIoY3RYihIrwHCL18GS+oCpZ+d9KBcCsKcENEFg6rv5Dl2Q/iHEwAAA0GZzVWNBt+sAAAAASUVORK5CYII=""/>"
#CSS style for the HTML report
$_header = @"
<style type="text/css">
    body
        {font-family: Helvetica, Arial, sans-serif; font-weight: normal;font-style: normal;color: black;}
    table
        {font-size:12px;color:black;width:100%;border-width: 1px;border-color: #729EA5;border-collapse: collapse;}
    th
        {font-size:12px;background-color:#66CBEA;border-width: 1px;padding: 8px;border-style: solid;border-color: #729EA5;text-align:left;}
    tr
        {background-color:#FFFFFF;}
    td
        {font-size:12px;border-width: 1px;padding: 8px;border-style: solid;border-color: #66CBEA;}
    tr:hover
        {background-color:#CAEDF8;}
    h1
        {border-bottom: 2px solid #66CBEA }
    h2
        {border-bottom: 2px solid #66CBEA }
    a
        {text-decoration: none;color:black}
</style>
"@
$_javascript_code = @"
    <script> 
    function showhide(id){ 
        if (document.getElementById){ 
            obj = document.getElementById(id); 
            if (obj.style.display == "none"){ 
                obj.style.display = ""; 
            } else { 
                obj.style.display = "none";
            } 
        } 
    } 
    </script>
"@
# Include or not the Javascript functions
If ( $_javascript -eq $false )
{
    $_output_body = "<h1>$($_ht_img["list"]) Timeline</h1><div id=""Timeline"">"
} Else {
    $_header += $_javascript_code 
    $_output_body = "<h1>$($_ht_img["list"]) <a href=""#"" onclick=""showhide('Timeline');""> Timeline</a></h1><div id=""Timeline"">"
}
# generate the HTML output for the Timeline section
$_output_year = ""
# The section <-and $_.Type -ne "Config"> is to remove the info about the current version of the schema for the output 
$_history | Where-Object { $_.Time -ne "N/A" -and $_.Type -ne "Config" } | Sort-Object Time | ForEach-Object `
{
    $_current_year = (Get-Date $_.Time).Year
    #If there it is a new year, then we prepare a nice title bar
    If ( $_current_year -ne $_output_year )
    {
        $_output_body += "<h2>$_current_year</h2>"        
    }
    $_output_body += "$($_ht_img[$_.Operation]) <b>$($_.Time)</b> $($_.Type) $($_.Context) $($_.Milestone) <br />"
    $_output_year = $_current_year 
}
$_output_body += "</div>"
If ( $_javascript -eq $false )
{
    $_output_body += "<h1>$($_ht_img["forest"]) Forest operations</h1><div id=""Forest"">"
} Else {
    $_output_body += "<h1>$($_ht_img["forest"]) <a href=""#"" onclick=""showhide('Forest');"">Forest operations</a></h1><div id=""Forest"">"
}
$_output_body += "<h2>$_forest_name</h2>"    
$_history | Where-Object { $_.Time -ne "N/A" -and $_.Type -eq "forest" } | Sort-Object Time | ForEach-Object `
{
    $_output_body += "$($_ht_img[$_.Operation]) <b>$($_.Time)</b> $($_.Type) $($_.Context) $($_.Milestone) <br />"
}
$_output_body += "</div>"
If ( $_javascript -eq $false )
{
    $_output_body += "<h1>$($_ht_img["domain"]) Per domain</h1><div id=""PerDomain"">"
} Else {
    $_output_body += "<h1>$($_ht_img["domain"]) <a href=""#"" onclick=""showhide('PerDomain');""> Per domain</a></h1><div id=""PerDomain"">"
}
# generate the HTML output for the Per domain section
$_output_domain = ""
$_history | Where-Object { $_.Time -ne "N/A" -and $_.Type -eq "domain" } | Sort-Object Context,Time | ForEach-Object `
{
    $_current_domain = $_.Context
    #If there it another domain, then we prepare a nice title bar
    If ( $_current_domain -ne $_output_domain )
    {
        $_output_body += "<h2>$_current_domain</h2>"        
    }
    $_output_body += "$($_ht_img[$_.Operation]) <b>$($_.Time)</b> $($_.Type) $($_.Context) $($_.Milestone) <br />"
    $_output_domain = $_current_domain 
}
$_output_body += "</div>"
$_output_body_title  = "<h1>$($_ht_img["forest"]) Active Directory Milestones</h1>" 
$_output_body_title += "<p><b>Forest:</b> $_forest_name<br/><b>Forest FFL:</b> $($_FLPattern[ [int] $_forest_lastffl_value])<br/><b>Schema version:</b> $($_SchemaPattern[$_forest_schema_level])<br/><b>User account:</b> $_collection_user_domain\$_collection_user_name<br/><b>Script version:</b> $_script_version<br/><b>Collection time:</b> $_script_end_collection seconds</p>"
# Include legend
If ( $_javascript -eq $false )
{
    $_output_body_title += "<p><b>Show legend</b><div id=""legend""></p>"
} Else {
    $_output_body_title += "<p><a href=""#"" onclick=""showhide('legend');""><b>Show legend</b></a><div id=""legend""></p>"
}
$_ht_img.Keys | ForEach-Object `
{
    $_current_key = $_
    switch ( $_current_key )
    {
        'infra'    { $_output_body_title += "$($_ht_img[$_current_key]) infrastructure modification<br/>" }
        'creation' { $_output_body_title += "$($_ht_img[$_current_key]) creation<br/>" }
        'forestup' { $_output_body_title += "$($_ht_img[$_current_key]) forest related upgrade<br/>" }
        'config'   { $_output_body_title += "$($_ht_img[$_current_key]) configuration related change<br/>" }
        'schema'   { $_output_body_title += "$($_ht_img[$_current_key]) schema update<br/>" }
        'domainup' { $_output_body_title += "$($_ht_img[$_current_key]) domain related upgrade<br/>" }
    }
}
$_output_body_title += "</div>"
#Generate the final output
ConvertTo-Html -Head $_header -Body $_output_body_title -PreContent $_output_body | Out-File $_output_report
#Display the report
Invoke-Item $_output_report