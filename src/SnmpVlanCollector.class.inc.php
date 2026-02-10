<?php

class SnmpVlanCollector extends SnmpCollector
{
	/**
	 * Retrieve and prepare VLANs discovered by {@see SnmpDiscoveryCollector}
	 * @return true
	 */
	public function Prepare(): bool
	{
		foreach (SnmpDiscoveryCollector::$aDiscoveredVLANs as $sKey => $aVLAN) {
			$aVLAN['primary_key'] = $sKey;
			$aVLAN['status'] = 'used';
			$this->aData[] = $aVLAN;
		}

		return parent::Prepare();
	}

	/**
	 * Collect device VLANs via SNMP
	 * @param SNMP $oSNMP
	 * @return array<int, array{
	 *     name: string,
	 *     interfaces_list: int[],
	 * }>
	 * @throws Exception
	 */
	public static function CollectVLANs(SNMP $oSNMP): array
	{
		$aVLANs = [];

		if (!filter_var(Utils::GetConfigurationValue('collect_vlans', false), FILTER_VALIDATE_BOOLEAN)) return $aVLANs;
		Utils::Log(LOG_DEBUG, "Collecting VLANs...");

		$dot1dBasePortIfIndex = @$oSNMP->walk('.1.3.6.1.2.1.17.1.4.1.2', true);
		$dot1qVlanCurrentEgressPorts = @$oSNMP->walk('.1.3.6.1.2.1.17.7.1.4.2.1.4', true);
		$dot1qVlanStaticName = @$oSNMP->walk('.1.3.6.1.2.1.17.7.1.4.3.1.1', true);

		if ($dot1qVlanCurrentEgressPorts !== false) foreach ($dot1qVlanCurrentEgressPorts as $sCurrentEntry => $sEgressPorts) {
			$aInterfaces = [];
			$iOffset = 0;
			foreach (unpack('C*', $sEgressPorts) as $iEgressPort) {
				foreach ([128, 64, 32, 16, 8, 4, 2, 1] as $iBitIndex => $iBit) {
					if ($iEgressPort & $iBit){
						$iPortIndex = $iOffset + $iBitIndex + 1;
						if (isset($dot1dBasePortIfIndex[$iPortIndex])) $aInterfaces[] = $dot1dBasePortIfIndex[$iPortIndex];
					}
				}
				$iOffset += 8;
			}

			$iTag = explode('.', $sCurrentEntry)[1];
			$aVLANs[$iTag] = [
				'name' => $dot1qVlanStaticName[$iTag] ?? $iTag,
				'interfaces_list' => $aInterfaces,
			];
		}

		Utils::Log(LOG_DEBUG, sprintf('%d VLANs collected', count($aVLANs)));
		return $aVLANs;
	}
}
