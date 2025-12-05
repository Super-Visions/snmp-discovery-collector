<?php

class IOSVersionCollector extends SnmpCollector
{
	/**
	 * Retrieve and prepare IOSVersions discovered by {@see SnmpDiscoveryCollector}
	 * @return true
	 */
	public function Prepare(): bool
	{
		foreach (SnmpDiscoveryCollector::$aDiscoveredVersions as $sBrand => $aDiscoveredVersions) {
			foreach ($aDiscoveredVersions as $sVersion) if (!empty($sVersion)) {
				$this->aData[] = [
					'primary_key' => sprintf('%s - %s', $sBrand, $sVersion),
					'brand_id' => $sBrand,
					'name' => $sVersion,
				];
			}
		}

		return parent::Prepare();
	}
}
