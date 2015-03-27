#requires -Module Posh-SSH
#region Get_RootCA
Function Get_RootCACert {
    [CmdletBinding()]
    Param(
        [parameter(mandatory=$true,ValueFromPipeline=$true,ValueFromPipelinebyPropertyName=$true)]
        [ValidateNotNullorEmpty()]
        [string]$RootCA,
        [Parameter()]
        [String[]]$rootcer
    )
If (!(test-path -Path $rootcer)){
   write-host "Downloading root certificate from $RootCA ..."
   # Renewal=-1 means get most recent cert
   $url = "http"+"://$RootCA/certsrv/certnew.cer?ReqID=CACert&Renewal=-1&Enc=b64"
   $wc = New-Object System.Net.WebClient
   $wc.UseDefaultCredentials = $true
   $wc.DownloadFile($url,$rootcer)
   If (!(test-path -Path $rootcer)) {write-host "$rootcer did not download" -foregroundcolor red;break}
   Write-host "Root CA download successful." -foregroundcolor yellow
   }
 Else { Write-host "Root CA file found, will not download." -ForegroundColor yellow} 

 $Validation = select-string -simple CERTIFICATE----- $rootcer
 If (!$Validation) {write-host "Invalid Root certificate format. Validate BASE64 encoding and try again." -foregroundcolor red}
}
#endregion
#region Cert_reqs
$VmwareCertReqs=@'
function vmware-cert-request {
IPADDRESS="$(/sbin/ifconfig 'eth0' | grep 'inet addr:' | cut -d: -f2 | awk '{ print $1}')"
COMPUTERNAME="${HOSTNAME%%.*}"
FILE="$(echo $1 | sed -e 's/ /_/g')"
cat >$FILE.cfg <<EOF
[ req ]
default_md = sha512
default_bits = 2048
default_keyfile = rui.key
distinguished_name = req_distinguished_name
encrypt_key = no
prompt = no
string_mask = nombstr
req_extensions = v3_req
input_password = testpassword
output_password = testpassword

[ v3_req ]
basicConstraints = CA:false
keyUsage = digitalSignature, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = DNS:$COMPUTERNAME, IP: $IPADDRESS, DNS: $HOSTNAME

[ req_distinguished_name ]
countryName = $2
stateOrProvinceName = $3
localityName = $4
0.organizationName = $5
organizationalUnitName = $1
commonName = $HOSTNAME
EOF
openssl req -new -nodes -out ./$FILE.csr -keyout ./$FILE.key -config ./$FILE.cfg
}

# Create Folder to put files
mkdir -p keys
cd keys
# Create Cert reqs
vmware-cert-request 'VMware vSphere Autodeploy Service Certificate' 'GB' 'Test' 'Test' 'Test'
vmware-cert-request 'VMware LogBrowser Service Certificate' 'GB' 'Test' 'Test' 'Test'
vmware-cert-request 'VMware Inventory Service Certificate' 'GB' 'Test' 'Test' 'Test'
vmware-cert-request 'VMware vCenter Service Certificate' 'GB' 'Test' 'Test' 'Test'
'@
#endregion
#region Setup VCA
$VCASetupScript=@'
# Author: William Lam
# Site: www.virtuallyghetto.com
# Reference: http://www.virtuallyghetto.com/2015/01/completely-automating-vcenter-server-appliance-vcsa-5-5-configurations.html

# User Configurations

# SSO Administrator password (administrator@vsphere.local)
SSO_ADMINISTRATOR_PASSWORD=vmware

# Join Active Directory (following 5 variables required)
JOIN_AD=0
AD_DOMAIN=primp-industries.com
AD_USER=administrator
AD_PASS=MYSUPERDUPERSTRONGPASSWORD
VCENTER_HOSTNAME=$HOSTNAME

# Enable NTP
ENABLE_NTP=0
NTP_SERVERS=0.pool.ntp.org

# VCSA expected Inentory Size (small, medium or large) - Details https://pubs.vmware.com/vsphere-55/index.jsp?topic=%2Fcom.vmware.vsphere.install.doc%2FGUID-67C4D2A0-10F7-4158-A249-D1B7D7B3BC99.html
VCSA_INVENTORY_SIZE=small

# Enable VMware Customer Experience Improvement Program
ENABLE_VC_TELEMTRY=0

################ DO NOT EDIT BEYOND HERE ################

# Method to check the return code from vpxd_servicefg which should return 0 for success
# This allows the script to validate the operations was successful without being so verbose 
# the output
checkStatusCode() {
        FILE=$1

        grep 'VC_CFG_RESULT=0' ${FILE} > /dev/null 2>&1
        if [ $? -eq 1 ]; then
                echo "Something went wrong, output from command:"
                cat ${FILE}
                exit 1;
        fi
}

setEula() {
        echo -e "\nAccepting VMware EULA ..."
        /usr/sbin/vpxd_servicecfg eula accept > /tmp/vcsa-deploy
        checkStatusCode /tmp/vcsa-deploy
}

setInventorySize() {
        echo "Configuring vCenter Server Inventory Size to ${VCSA_INVENTORY_SIZE} ..."

        if [ ${VCSA_INVENTORY_SIZE} == "medium" ]; then
                /usr/sbin/vpxd_servicecfg 'jvm-max-heap' 'write' '512' '6144' '2048' > /tmp/vcsa-deploy
                checkStatusCode /tmp/vcsa-deploy
        elif [ ${VCSA_INVENTORY_SIZE} == "large" ]; then
                /usr/sbin/vpxd_servicecfg 'jvm-max-heap' 'write' '1024' '12288' '4096' > /tmp/vcsa-deploy
                checkStatusCode /tmp/vcsa-deploy
        else #default to small
                /usr/sbin/vpxd_servicecfg 'jvm-max-heap' 'write' '512' '3072' '1024' > /tmp/vcsa-deploy
                checkStatusCode /tmp/vcsa-deploy
        fi
}

setActiveDirectory() {
        if [ ${JOIN_AD} -eq 1 ]; then
                echo "Configuring vCenter Server hostname ..."
                SHORTHOSTNAME=$(echo ${VCENTER_HOSTNAME} |  cut -d. -f1)
                /bin/hostname ${VCENTER_HOSTNAME}

                echo ${VCENTER_HOSTNAME} > /etc/HOSTNAME
                sed -i "s/localhost/${SHORTHOSTNAME}/g" /etc/hosts

                echo "Configuring Active Directory ..."
                /usr/sbin/vpxd_servicecfg ad write "${AD_USER}" "${AD_PASS}" ${AD_DOMAIN} > /tmp/vcsa-deploy
                checkStatusCode /tmp/vcsa-deploy

                echo "Adding DNS Search Domain ..."
                echo "search ${AD_DOMAIN}" >> /etc/resolv.conf

                echo "Enabling SSL Certificate re-generation, please ensure you REBOOT once the script completes ..."
                touch /etc/vmware-vpx/ssl/allow_regeneration
        fi
}

setNTP() {
echo "Enbaling Time Synchronization ..."
        if [ ${ENABLE_NTP} -eq 1 ]; then
                /usr/sbin/vpxd_servicecfg timesync write ntp ${NTP_SERVERS} > /tmp/vcsa-deploy
                checkStatusCode /tmp/vcsa-deploy
        else
                /usr/sbin/vpxd_servicecfg timesync write tools > /tmp/vcsa-deploy
                checkStatusCode /tmp/vcsa-deploy
        fi
}

setVCDB() {
        echo "Configuring vCenter Server Embedded DB ..."
        /usr/sbin/vpxd_servicecfg db write embedded &> /tmp/vcsa-deploy
        checkStatusCode /tmp/vcsa-deploy
}

setSSODB() {
        echo "Configuring vCenter Server SSO w/custom administrator@vsphere.local password ..."
        /usr/sbin/vpxd_servicecfg sso write embedded ${SSO_ADMINISTRATOR_PASSWORD} > /tmp/vcsa-deploy
        checkStatusCode /tmp/vcsa-deploy
}

setSSOIdentitySource() {
        if [ ${JOIN_AD} -eq 1 ]; then
                echo "Adding Active Directory Identity Source to SSO ..."
                # Reference http://kb.vmware.com/kb/2063424
                EXPORTED_SSO_PROPERTIES=/usr/lib/vmware-upgrade/sso/exported_sso.properties
                if [ -e ${EXPORTED_SSO_PROPERTIES} ] ;then
                        rm -f  ${EXPORTED_SSO_PROPERTIES}
                fi

                cat > ${EXPORTED_SSO_PROPERTIES} << __SSO_EXPORT_CONF__
ExternalIdentitySource.${AD_DOMAIN}.name=${AD_DOMAIN}
ExternalIdentitySource.${AD_DOMAIN}.type=0
ExternalIdentitySourcesDomainNames=${AD_DOMAIN}
__SSO_EXPORT_CONF__

                /usr/lib/vmware-upgrade/sso/sso_import.sh > /dev/null 2>&1
                rm -rf ${EXPORTED_SSO_PROPERTIES}

                echo "Configuring ${AD_DOMAIN} as default Identity Source ..."
                # Reference http://kb.vmware.com/kb/2070433
                SSO_LDIF_CONF=/tmp/defaultdomain.ldif
                cat > ${SSO_LDIF_CONF} << __DEFAULT_SSO_DOMAIN__
dn: cn=vsphere.local,cn=Tenants,cn=IdentityManager,cn=Services,dc=vsphere,dc=local
changetype: modify
replace: vmwSTSDefaultIdentityProvider
vmwSTSDefaultIdentityProvider: ${AD_DOMAIN}
__DEFAULT_SSO_DOMAIN__
                ldapmodify -f ${SSO_LDIF_CONF} -h localhost -p 11711 -D "cn=Administrator,cn=Users,dc=vsphere,dc=local" -w ${SSO_ADMINISTRATOR_PASSWORD} > /dev/null 2>&1
                if [ $? -eq 1 ]; then
                        echo "Unable to update Default SSO Domain for some reason"
                        exit 1
                fi
                rm -f ${SSO_LDIF_CONF}
        fi
}

startVC() {
        echo "Starting the vCenter Server Service ..."
        /usr/sbin/vpxd_servicecfg service start > /tmp/vcsa-deploy
        checkStatusCode /tmp/vcsa-deploy
}

setVCTelemtry() {
        if [[ -e /var/log/vmware/phonehome ]] && [[ ${ENABLE_VC_TELEMTRY} -eq 1 ]]; then
                echo "Enabling vCenter Server Telemtry ..."
                /usr/sbin/vpxd_servicecfg telemetry enable > /tmp/vcsa-deploy
                checkStatusCode /tmp/vcsa-deploy
        fi
}

### START OF SCRIPT ### 

setEula
setInventorySize
setActiveDirectory  
setNTP
setVCDB
setSSODB
setSSOIdentitySource  
startVC
setVCTelemtry
'@

#endregion
#region Install
$VmwareInstallScript=@'
mkdir -p /root/ssl/{vpxd,inventoryservice,logbrowser,autodeploy}
cd /root/keys
# Copy Certs into working folders
cp VMware_vCenter_Service_Certificate.cer /root/ssl/vpxd/rui.crt
cp VMware_vCenter_Service_Certificate.key /root/ssl/vpxd/rui.key
cp VMware_Inventory_Service_Certificate.cer /root/ssl/inventoryservice/rui.crt
cp VMware_Inventory_Service_Certificate.key /root/ssl/inventoryservice/rui.key
cp VMware_LogBrowser_Service_Certificate.cer /root/ssl/logbrowser/rui.crt
cp VMware_LogBrowser_Service_Certificate.key /root/ssl/logbrowser/rui.key
cp VMware_vSphere_Autodeploy_Service_Certificate.cer /root/ssl/autodeploy/rui.crt
cp VMware_vSphere_Autodeploy_Service_Certificate.key /root/ssl/autodeploy/rui.key
cp RootCA.cer /root/ssl/cachain.cer
# Convert cachain
cd /root/ssl
cp cachain.cer cachain.pem
#openssl pkcs7 -print_certs -in cachain.cer -out cachain.pem
# Remove extra information from cachain.pem
sed -i 's/^subject.*//g' cachain.pem
sed -i 's/^issuer.*//g' cachain.pem
# Copy cachain.pem to working folders
cp /root/ssl/cachain.pem /root/ssl/inventoryservice
cp /root/ssl/cachain.pem /root/ssl/logbrowser
cp /root/ssl/cachain.pem /root/ssl/vpxd
# vCenter Services configuration
# Stop services
service vmware-stsd stop
service vmware-vpxd stop
# Combine cert and cachain
cd /root/ssl/vpxd
cat rui.crt cachain.pem > chain.pem
# Replace self-signed cert with proper CA signed Cert
/usr/sbin/vpxd_servicecfg certificate change chain.pem rui.key
# Restart Service
service vmware-stsd start
# Inventory Service configuration
# Unregister Inventory Service
/etc/vmware-sso/register-hooks.d/02-inventoryservice --mode uninstall --ls-server https://$HOSTNAME:7444/lookupservice/sdk
# Copy Cert
cd /root/ssl/inventoryservice
cat rui.crt cachain.pem > chain.pem
# Convert to pfx file, Don't change password it will break vcenter
openssl pkcs12 -export -out rui.pfx -in chain.pem -inkey rui.key -name rui -passout pass:testpassword
# Copy files to new location
cp rui.key /usr/lib/vmware-vpx/inventoryservice/ssl
cp rui.crt /usr/lib/vmware-vpx/inventoryservice/ssl
cp rui.pfx /usr/lib/vmware-vpx/inventoryservice/ssl
# Change Permissions on Files
cd /usr/lib/vmware-vpx/inventoryservice/ssl/
chmod 400 rui.key rui.pfx
chmod 644 rui.crt
# Register Inventory service
/etc/vmware-sso/register-hooks.d/02-inventoryservice --mode install --ls-server https://$HOSTNAME:7444/lookupservice/sdk --user administrator@vsphere.local --password vmware
# Re-Associate Invenrtory service
rm /var/vmware/vpxd/inventoryservice_registered
service vmware-inventoryservice stop
service vmware-vpxd stop
service vmware-inventoryservice start
service vmware-vpxd start
# Log Browser configuration
# Unregister
/etc/vmware-sso/register-hooks.d/09-vmware-logbrowser --mode uninstall --ls-server https://$HOSTNAME:7444/lookupservice/sdk
# Copy Cert
cd /root/ssl/logbrowser
cat rui.crt cachain.pem > chain.pem
# Convert to pfx file, Don't change password it will break vcenter
openssl pkcs12 -export -out rui.pfx -in chain.pem -inkey rui.key -name rui -passout pass:testpassword
# Copy Files
cp rui.key /usr/lib/vmware-logbrowser/conf
cp rui.crt /usr/lib/vmware-logbrowser/conf
cp rui.pfx /usr/lib/vmware-logbrowser/conf
# Change Permissions
cd /usr/lib/vmware-logbrowser/conf
chmod 400 rui.key rui.pfx
chmod 644 rui.crt
# Register Service
/etc/vmware-sso/register-hooks.d/09-vmware-logbrowser --mode install --ls-server https://$HOSTNAME:7444/lookupservice/sdk --user administrator@vsphere.local --password vmware
# restart
service vmware-logbrowser stop
service vmware-logbrowser start
# Autodeploy
# Copy Certs
cp /root/ssl/autodeploy/rui.crt /etc/vmware-rbd/ssl/waiter.crt
cp /root/ssl/autodeploy/rui.key /etc/vmware-rbd/ssl/waiter.key
# Update Permissions
cd /etc/vmware-rbd/ssl/
chmod 644 waiter.crt
chmod 400 waiter.key
chown deploy:deploy waiter.crt waiter.key
# Register Service
service vmware-rbd-watchdog stop
rm /var/vmware/vpxd/autodeploy_registered
service vmware-vpxd restart
# Reboot
shutdown -r now
'@
#endregion
#region Variables
$SSHServer="192.168.1.1"
$SSHUSER="root"
$SSHPass=ConvertTo-SecureString 'vmware' -asplaintext -force
$CARoot="MYCAServer"
$CA="MYCAServer\MYCAServer"
$CertTemplate = "VMwareCertificate" # must always use concatenated name format needs to exist 
#endregion

$SSHCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $SSHuser,$SSHpass
Remove-SSHTrustedHost -SSHHost $SSHServer
$SSHSession=New-SSHSession -Computername $SSHServer -Credential $SSHCredential -ConnectionTimeout 999
clear
write-host "Setting up VCA"
Invoke-SSHCommand $SSHSession -Command $VCASetupScript -TimeOut 9999
Write-Host "Generating Cert Reqs"
Invoke-SSHCommand $SSHSession -Command $VmwareCertReqs -TimeOut 999
Write-Host "Copying Cert Reqs"
# get files from server
mkdir $SSHServer
cd $SSHServer
$SFTPSession=New-SFTPSession -Computername $SSHServer -Credential $SSHCredential
$SSHCSRFiles=(Get-SFTPChildItem -SFTPSession $SFTPSession -Path "/root/keys") | where {($_.IsDirectory -eq $false) -and ($_.Name -like "*.csr")}
Foreach ($File in $SSHCSRFiles) {
$RemoteFile=$File.FullName
$LocalFile="$PWD\$($File.Name)"
Get-SCPFile -Computername $SSHServer -Credential $SSHCredential -RemoteFile "$RemoteFile" -LocalFile "$LocalFile"
$RemoteFile=$null
$LocalFile=$null
}
Write-Host "Generating Certs"
# create der encoded certs from ca
$CSRFiles=(Get-ChildItem -Path "$PWD") | where {($_.PSIsContainer -eq $false) -and ($_.extension -eq ".csr")}
Foreach ($File in $CSRFiles) {
$CSRFile=$File.FullName
$CERFile=$CSRFile.Replace("csr","cer")
$P7BFile=$CSRFile.Replace("csr","p7b")
certreq.exe -submit  -attrib CertificateTemplate:$CertTemplate -config "$CA" "$CSRFile" "$CERFile" "$P7BFile"
}
# Download Root CA
Write-Host "Getting CA Root"
Get_RootCACert -RootCA "$CARoot" -rootcer "$PWD\RootCA.cer"
Write-Host "Uploading Certs to VCA"
# upload cert to linux
$CERTFiles=(Get-ChildItem -Path "$PWD") | where {($_.PSIsContainer -eq $false) -and (($_.extension -like "*.cer") -or ($_.extension -like "*.p7b"))}
Foreach ($File in $CERTFiles) {
$LocalFile=$File.FullName
Set-SCPFile -Computername $SSHServer -Credential $SSHCredential -LocalFile "$LocalFile" -RemotePath "/root/keys" 
$LocalFile=$null
}

# apply certs
Write-Host "Installing Certs on VCA"
Invoke-SSHCommand $SSHSession -Command $VmwareInstallScript -TimeOut 9999
