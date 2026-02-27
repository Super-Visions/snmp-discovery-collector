<?php

class SnmpCollectionPlan extends CollectionPlan
{
	/** @var bool Whether interfaces also need to be collected */
	protected bool $bCollectInterfaces;

	/**
	 * @inheritDoc
	 */
	public function Init(): void
	{
		parent::Init();

		// Check if modules are installed
		Utils::CheckModuleInstallation('sv-snmp-discovery/1.3.0', true);

		$this->bCollectInterfaces = filter_var(Utils::GetConfigurationValue('collect_interfaces', false), FILTER_VALIDATE_BOOLEAN);
	}

	/**
	 * @inheritDoc
	 * @return true
	 */
	public function AddCollectorsToOrchestrator(): bool
	{
		$iOrder = 0;

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
}
