<?php

class ModelCollector extends SnmpCollector
{
	/**
	 * Retrieve and prepare Models discovered by {@see SnmpDiscoveryCollector}
	 * @return true
	 */
	public function Prepare(): bool
	{
		foreach (SnmpDiscoveryCollector::$aDiscoveredModels as $sBrand => $aDiscoveredModels) {
			foreach ($aDiscoveredModels as $sModel) if (!empty($sModel)) {
				$this->aData[] = [
					'primary_key' => sprintf('%s - %s', $sBrand, $sModel),
					'brand_id' => $sBrand,
					'name' => $sModel,
					'type' => 'NetworkDevice',
				];
			}
		}

		return parent::Prepare();
	}
}
