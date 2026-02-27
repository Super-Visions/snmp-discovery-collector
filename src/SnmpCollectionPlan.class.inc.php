<?php

class SnmpCollectionPlan extends CollectionPlan
{
	/** @var bool Whether interfaces also need to be collected */
	protected bool $bCollectInterfaces;
	/** @var int The `SNMPDiscovery` ID */
	protected int $iApplicationID = 0;
	/**
	 * @var array<string, array{
	 *     default_org_id: int,
	 *     default_networkdevicetype_id: int,
	 *     snmpcredentials_list: int[],
	 * }> List of subnets with their configured parameters
	 */
	protected array $aSubnets = [];

	/**
	 * @inheritDoc
	 */
	public function Init(): void
	{
		parent::Init();

		// Check if modules are installed
		Utils::CheckModuleInstallation('sv-snmp-discovery/1.3.0', true);

		// Load SNMP discovery application settings
		$this->LoadApplicationSettings();

		$this->bCollectInterfaces = filter_var(Utils::GetConfigurationValue('collect_interfaces', false), FILTER_VALIDATE_BOOLEAN);
	}

	/**
	 * @inheritDoc
	 * @return true
	 */
	public function AddCollectorsToOrchestrator(): bool
	{
		$iOrder = 1;

		Orchestrator::AddCollector($iOrder++, ModelCollector::class);
		Orchestrator::AddCollector($iOrder++, IOSVersionCollector::class);
		Orchestrator::AddCollector($iOrder++, SnmpDiscoveryCollector::class);

		if ($this->bCollectInterfaces) {
			Orchestrator::AddCollector($iOrder++, PhysicalInterfaceCollector::class);
			Orchestrator::AddCollector($iOrder++, VirtualInterfaceCollector::class);
			Orchestrator::AddCollector($iOrder++, AggregateLinkCollector::class);
		}

		return true;
	}

	/**
	 * Load the SNMP discovery application ID and subnet(s) to discover.
	 * @return void
	 * @throws Exception
	 */
	protected function LoadApplicationSettings(): void
	{
		$sUUID = Utils::GetConfigurationValue('discovery_application_uuid');
		$oRestClient = new RestClient();

		try {
			$aResults = $oRestClient->Get('SNMPDiscovery', ['uuid' => $sUUID], 'ipv4subnets_list,ipv6subnets_list');
			if ($aResults['code'] != 0 || empty($aResults['objects'])) {
				throw new Exception($aResults['message'], $aResults['code']);
			}

			$aDiscovery = current($aResults['objects']);
			$this->iApplicationID = (int)$aDiscovery['key'];

			Utils::Log(LOG_INFO, sprintf('An SNMP discovery application with UUID %s has been found in iTop.', $sUUID));
		} catch (Exception $e) {
			throw new Exception(sprintf('An SNMP discovery application with UUID %s could not be found: %s', $sUUID, $e->getMessage()), 0, $e);
		}

		// Prepare IPv4 subnet info
		foreach ($aDiscovery['fields']['ipv4subnets_list'] as $aSubnet) {
			$this->LoadSubnet($aSubnet);
		}

		// Prepare IPv6 subnet info
		foreach ($aDiscovery['fields']['ipv6subnets_list'] as $aSubnet) {
			$this->LoadSubnet($aSubnet);
		}

		Utils::Log(LOG_INFO, count($this->aSubnets) . ' subnets to discover.');
	}

	/**
	 * Prepare the subnet parameters list by the given subnet.
	 * @param array{
	 *     ip: string,
	 *     org_id: string,
	 *     default_networkdevicetype_id: string,
	 *     snmpcredentials_list: int[],
	 *     ipdiscovery_enabled: string,
	 * } $aSubnet
	 * @return void
	 * @throws Exception
	 * @noinspection SpellCheckingInspection
	 */
	protected function LoadSubnet(array $aSubnet): void
	{
		if ($aSubnet['ipdiscovery_enabled'] == 'yes') {
			$this->aSubnets[$aSubnet['ip']] = [
				'default_org_id' => (int)$aSubnet['org_id'],
				'default_networkdevicetype_id' => (int)$aSubnet['default_networkdevicetype_id'],
				'snmpcredentials_list' => array_map(function ($aListItem) { return (int)$aListItem['snmpcredentials_id']; }, $aSubnet['snmpcredentials_list']),
			];

			if (empty($aSubnet['default_networkdevicetype_id'])) {
				Utils::Log(LOG_WARNING, sprintf('No default networkdevicetype_id set for subnet %s, creation of new devices might fail.', $aSubnet['ip']));
			}
		}
	}

	/**
	 * Get the ID of the SNMP discovery application found with the given UUID
	 * @return int
	 */
	public function GetApplicationID(): int
	{
		return $this->iApplicationID;
	}

	/**
	 * Get the list of subnets with their configured parameters
	 * @return array<string, array{
	 *      default_org_id: int,
	 *      default_networkdevicetype_id: int,
	 *      snmpcredentials_list: int[],
	 *  }>
	 */
	public function GetSubnets(): array
	{
		return $this->aSubnets;
	}
}
