Function Replace-VM-RDM {
param($vmname, $scsiid, $rdmname, $filename)
<#
Convert the SCSI address in to Vmware format
#>
$scsicontroller=$null
$scsiid_split=$null
$scsiid_split=$scsiid.split(":")
$scsicontroller=($scsiid_split[0])
# VMware SCSI controller ID in gui is one number higher than the actual controller id
$scsicontroller=[int]$scsicontroller+1
# Vmware expects a conntroller id with 4 chars
$scsicontroller=($scsicontroller.ToString())+"000"
# SCSI LUN
$scsilun=$null
# VMware SCSI LUN ID in gui is one number higher than the actual lun id
$scsilun=[int]($scsiid_split[1])#+1

###
#Remove RDM from VM
###
$vm = Get-VM -Name "$vmname" | Get-View

foreach($dev in $vm.Config.Hardware.Device){
    if(($dev.gettype()).Name -eq "VirtualDisk"){
        if(($dev.Backing.CompatibilityMode -eq "physicalMode") -or 
        ($dev.Backing.CompatibilityMode -eq "virtualMode")){
			if (($dev.ControllerKey -eq "$scsicontroller") -and ($dev.UnitNumber -eq "$scsilun")) {
				# Remove Harddisk
				$hd=get-harddisk $vm.name | where {$_.Filename -eq $dev.Backing.FileName} 
				$hd | remove-harddisk -confirm:$false -DeletePermanently
				Write-Host "Removed RDM at [$scsiid]" -background blue -foreground white}
		}
		Elseif (($dev.ControllerKey -eq "$scsicontroller") -and ($dev.UnitNumber -eq "$scsilun")) {Write-Host "Selected SCSI Address [$scsiid] is not a RDM"}
    }
}
<#
Get for RDM LUN details

#>
$esx = Get-View $vm.Runtime.Host
$disk=($esx.Config.StorageDevice.ScsiLun | where {$_.DisplayName -eq $rdmname})
$rdmCanonicalName=$disk.CanonicalName
$rdmDevicePath=$disk.DevicePath
$rdmcapacity=($disk.Capacity.Block * $disk.Capacity.BlockSize) / 1Kb
IF (!($filename)){
$RDMFile=$rdmname.split(" ")[0]+"_RDM.vmdk"
$filename=(($vm.Config.Files.VmPathName).Replace("$vmname.vmx","$RDMFile"))
}

	$spec=$null
	$spec = New-Object VMware.Vim.VirtualMachineConfigSpec
	$spec.deviceChange = New-Object VMware.Vim.VirtualDeviceConfigSpec[] (1)
	$spec.deviceChange[0] = New-Object VMware.Vim.VirtualDeviceConfigSpec
	# Create vmdk file
	$spec.deviceChange[0].fileOperation = "create"
	$spec.deviceChange[0].operation = "add"
	$spec.deviceChange = New-Object VMware.Vim.VirtualDeviceConfigSpec[] (1)
	$spec.deviceChange[0] = New-Object VMware.Vim.VirtualDeviceConfigSpec
	$spec.deviceChange[0].operation = "add"
	$spec.deviceChange[0].fileOperation = "create"
	$spec.deviceChange[0].device = New-Object VMware.Vim.VirtualDisk
	$spec.deviceChange[0].device.key = -100
	$spec.deviceChange[0].device.backing = New-Object VMware.Vim.VirtualDiskRawDiskMappingVer1BackingInfo
	$spec.deviceChange[0].device.backing.fileName = "$filename"
	$spec.deviceChange[0].device.backing.deviceName = "$rdmDevicePath"
	$spec.deviceChange[0].device.backing.compatibilityMode = "physicalMode"
	$spec.deviceChange[0].device.backing.diskMode = ""
	$spec.deviceChange[0].device.connectable = New-Object VMware.Vim.VirtualDeviceConnectInfo
	$spec.deviceChange[0].device.connectable.startConnected = $true
	$spec.deviceChange[0].device.connectable.allowGuestControl = $false
	$spec.deviceChange[0].device.connectable.connected = $true
# SCSI controller device key
	$spec.deviceChange[0].device.controllerKey = [int]$scsicontroller
# The UnitNUmber SCSIID 7 is reserved for the Controller - so skip to 8.
	if ($scsilun -eq 6) {$scsilun = $scsilun + 1}
# Take next unit number for HD
	$spec.deviceChange[0].device.unitnumber = [int]$scsilun 
	$spec.deviceChange[0].device.capacityInKB = [int]$rdmcapacity
	$vm = Get-View (Get-VM $VMname).ID
	$vm.ReconfigVM($spec)
	Write-Host "Added RDM $rdmname with Capacity $rdmcapacity (KB) at SCSI ID [$scsiid]" -background green -foreground black
}