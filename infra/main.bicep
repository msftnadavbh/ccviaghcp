targetScope = 'subscription'

@allowed(['foundation', 'aks'])
param phase string = 'foundation'
param operatorObjectId string
param operatorCidr string
param expectedSubscriptionId string
param expectedTenantId string
@secure()
param adminPassword string

// A mismatch skips resources/modules; it need not make ARM validation fail.
var scopeMatches = subscription().subscriptionId == expectedSubscriptionId && tenant().tenantId == expectedTenantId
resource rg 'Microsoft.Resources/resourceGroups@2024-03-01' = if (scopeMatches) {
  name: 'ccviaghcp-rg'
  location: 'swedencentral'
}
module foundation './foundation.bicep' = if (scopeMatches && phase == 'foundation') {
  name: 'ccviaghcp-foundation'
  scope: rg
  params: { adminPassword: adminPassword }
}
resource natPip 'Microsoft.Network/publicIPAddresses@2025-01-01' existing = {
  name: 'ccviaghcp-nat-pip'
  scope: rg
}
resource aksIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' existing = {
  name: 'ccviaghcp-aks-control'
  scope: rg
}
module aks './aks.bicep' = if (scopeMatches && phase == 'aks') {
  name: 'ccviaghcp-aks'
  scope: rg
  params: {
    operatorObjectId: operatorObjectId
    operatorCidr: operatorCidr
    expectedTenantId: expectedTenantId
    natCidr: (scopeMatches && phase == 'aks') ? '${natPip.properties.ipAddress}/32' : ''
    identityId: aksIdentity.id
  }
}
