$username = "relic"
$service = "relic"

Add-Type -AssemblyName System.Web
$password = [System.Web.Security.Membership]::GeneratePassword(32,0)
#write-host "Password: $password"

$user = [ADSI]"WinNT://./$username,user"
if ($user.Name -eq $null) {
    write-host "User $username does not exist"
    exit 1
}
$user.Description = "Secure package signing service"
$user.SetInfo()
$user.SetPassword($password)
write-host "Updated user password"

$obj = Get-WmiObject win32_service -filter "name='$service'"
$status = $obj.change($null,$null,$null,$null,$null,$null,".\$username",$password,$null,$null,$null)
if ($status.ReturnValue -eq "0") {
    write-host "Updated service logon"
} else {
    write-host "Failed to update service"
}
