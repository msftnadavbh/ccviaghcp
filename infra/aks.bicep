param operatorObjectId string
param operatorCidr string
param natCidr string
param identityId string
param expectedTenantId string
resource cluster 'Microsoft.ContainerService/managedClusters@2025-01-01' = {
  name: 'ccviaghcp-aks'
  location: 'swedencentral'
  sku: { name: 'Base', tier: 'Free' }
  identity: { type: 'UserAssigned', userAssignedIdentities: { '${identityId}': {} } }
  properties: {
    kubernetesVersion: '1.36.4'
    dnsPrefix: 'ccviaghcp'
    nodeResourceGroup: 'ccviaghcp-aks-nodes-rg'
    enableRBAC: true
    disableLocalAccounts: true
    aadProfile: {
      managed: true
      enableAzureRBAC: true
      tenantID: expectedTenantId
    }
    apiServerAccessProfile: { authorizedIPRanges: [operatorCidr, natCidr] }
    agentPoolProfiles: [{
      name: 'system'
      mode: 'System'
      count: 2
      vmSize: 'Standard_D4s_v5'
      osType: 'Linux'
      osSKU: 'Ubuntu'
      type: 'VirtualMachineScaleSets'
      enableAutoScaling: false
      vnetSubnetID: resourceId('Microsoft.Network/virtualNetworks/subnets', 'ccviaghcp-vnet', 'aks')
      maxPods: 30
      upgradeSettings: { maxSurge: '1' }
    }]
    networkProfile: {
      networkPlugin: 'azure'
      networkPluginMode: 'overlay'
      networkDataplane: 'cilium'
      networkPolicy: 'cilium'
      outboundType: 'userAssignedNATGateway'
      loadBalancerSku: 'standard'
      podCidr: '10.78.0.0/16'
      serviceCidr: '10.79.0.0/16'
      dnsServiceIP: '10.79.0.10'
    }
  }
}
resource adminRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(cluster.id, operatorObjectId, 'rbac-cluster-admin')
  scope: cluster
  properties: {
    principalId: operatorObjectId
    principalType: 'User'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b1ff04bb-8a4e-4dc4-8eb5-8693973ce19b')
  }
}
resource credentialRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(cluster.id, operatorObjectId, 'cluster-user')
  scope: cluster
  properties: {
    principalId: operatorObjectId
    principalType: 'User'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4abbcc35-e782-43d8-92c5-2d3f1bd2253f')
  }
}
