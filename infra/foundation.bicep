@secure()
param adminPassword string
var location = 'swedencentral'

resource pip 'Microsoft.Network/publicIPAddresses@2025-01-01' = {
  name: 'ccviaghcp-nat-pip'
  location: location
  sku: {
    name: 'Standard'
    tier: 'Regional'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
    publicIPAddressVersion: 'IPv4'
    ddosSettings: { protectionMode: 'VirtualNetworkInherited' }
  }
}
resource nat 'Microsoft.Network/natGateways@2025-01-01' = {
  name: 'ccviaghcp-nat'
  location: location
  sku: { name: 'Standard' }
  properties: {
    idleTimeoutInMinutes: 10
    publicIpAddresses: [{ id: pip.id }]
  }
}
resource nsg 'Microsoft.Network/networkSecurityGroups@2025-01-01' = {
  name: 'ccviaghcp-windows-nsg'
  location: location
  properties: {
    securityRules: [
      // Deny-only by default; any manual access path requires operator review.
      {
        name: 'DenyOtherInbound'
        properties: {
          priority: 200
          direction: 'Inbound'
          access: 'Deny'
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '*'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
        }
      }
    ]
  }
}
resource vnet 'Microsoft.Network/virtualNetworks@2025-01-01' = {
  name: 'ccviaghcp-vnet'
  location: location
  properties: {
    addressSpace: { addressPrefixes: ['10.77.0.0/16'] }
    subnets: [
      {
        name: 'aks'
        properties: { addressPrefix: '10.77.0.0/24', natGateway: { id: nat.id } }
      }
      {
        name: 'windows'
        properties: {
          addressPrefix: '10.77.1.0/27'
          natGateway: { id: nat.id }
          networkSecurityGroup: { id: nsg.id }
        }
      }
    ]
  }
}
resource zone 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  name: 'ccviaghcp.test'
  location: 'global'
}
resource link 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: zone
  name: 'ccviaghcp'
  location: 'global'
  properties: { registrationEnabled: false, virtualNetwork: { id: vnet.id } }
}
resource record 'Microsoft.Network/privateDnsZones/A@2024-06-01' = {
  parent: zone
  name: 'litellm'
  properties: { ttl: 300, aRecords: [{ ipv4Address: '10.77.0.240' }] }
}
resource bastion 'Microsoft.Network/bastionHosts@2025-01-01' = {
  name: 'ccviaghcp-bastion'
  location: location
  sku: { name: 'Developer' }
  properties: { virtualNetwork: { id: vnet.id } }
}
resource nic 'Microsoft.Network/networkInterfaces@2025-01-01' = {
  name: 'ccviaghcp-windows-nic'
  location: location
  properties: {
    enableAcceleratedNetworking: true
    ipConfigurations: [{
      name: 'private'
      properties: {
        privateIPAllocationMethod: 'Static'
        privateIPAddress: '10.77.1.4'
        subnet: { id: '${vnet.id}/subnets/windows' }
      }
    }]
  }
}
resource vm 'Microsoft.Compute/virtualMachines@2024-11-01' = {
  name: 'ccviaghcp-windows'
  location: location
  properties: {
    hardwareProfile: { vmSize: 'Standard_D2s_v5' }
    licenseType: 'Windows_Client'
    securityProfile: {
      securityType: 'TrustedLaunch'
      uefiSettings: { secureBootEnabled: true, vTpmEnabled: true }
    }
    storageProfile: {
      imageReference: {
        publisher: 'MicrosoftWindowsDesktop'
        offer: 'windows-11'
        sku: 'win11-25h2-ent'
        version: '26200.9711.261011'
      }
      osDisk: {
        createOption: 'FromImage'
        managedDisk: { storageAccountType: 'StandardSSD_LRS' }
      }
    }
    osProfile: {
      computerName: 'ccviaghcp-win'
      adminUsername: 'ccviaghcpuser'
      adminPassword: adminPassword
      windowsConfiguration: {
        provisionVMAgent: true
        enableAutomaticUpdates: true
      }
    }
    networkProfile: { networkInterfaces: [{ id: nic.id }] }
  }
}
resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'ccviaghcp-aks-control'
  location: location
}
resource networkRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(vnet.id, identity.id, 'network-contributor')
  scope: vnet
  properties: {
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4d97b98b-1d4f-4787-a291-c67834d212e7')
  }
}
output natIp string = pip.properties.ipAddress
output identityId string = identity.id
