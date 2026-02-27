<?php

class SnmpCollectionPlan extends CollectionPlan
{
	protected array $aLaunchSequence = [];

	public function Init(): void
	{
		parent::Init();

		$bCollectInterfaces = filter_var(Utils::GetConfigurationValue('collect_interfaces', false), FILTER_VALIDATE_BOOLEAN);

		$this->aLaunchSequence = [
			[
				'name' => ModelCollector::class,
				'enable' => 'yes',
			],
			[
				'name' => IOSVersionCollector::class,
				'enable' => 'yes',
			],
			[
				'name' => SnmpDiscoveryCollector::class,
				'enable' => 'yes',
			],
			[
				'name' => PhysicalInterfaceCollector::class,
				'enable' => $bCollectInterfaces ? 'yes' : 'no',
			],
			[
				'name' => VirtualInterfaceCollector::class,
				'enable' => $bCollectInterfaces ? 'yes' : 'no',
			],
			[
				'name' => AggregateLinkCollector::class,
				'enable' => $bCollectInterfaces ? 'yes' : 'no',
			],
		];
	}

	public function GetSortedLaunchSequence(): array
	{
		return $this->aLaunchSequence;
	}

	function GetCollectorDefinitionFile($sCollector): bool
	{
		return match ($sCollector) {
			PhysicalInterfaceCollector::class,
			VirtualInterfaceCollector::class,
			AggregateLinkCollector::class => parent::GetCollectorDefinitionFile(SnmpInterfaceCollector::class),
			default => parent::GetCollectorDefinitionFile($sCollector),
		};
	}
}
