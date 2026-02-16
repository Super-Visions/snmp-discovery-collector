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
			$this->aData[] = [
				'primary_key' => $sKey,
				'vlan_tag' => $aVLAN['tag'],
				'name' => $aVLAN['name'],
				'org_id' => $aVLAN['org_id'],
				'status' => $aVLAN['used'] ? 'used' : 'reserved',
			];
		}

		return parent::Prepare();
	}

	/**
	 * Collect device VLANs via SNMP
	 * @param SNMP $oSNMP
	 * @param string $sSysObjectID
	 * @return array<int, array{
	 *     name: string,
	 *     interfaces_list: int[],
	 *     untagged_interfaces_list: int[],
	 * }>
	 * @throws Exception
	 */
	public static function CollectVLANs(SNMP $oSNMP, string $sSysObjectID): array
	{
		$aVLANs = [];

		if (!filter_var(Utils::GetConfigurationValue('collect_vlans', false), FILTER_VALIDATE_BOOLEAN)) return $aVLANs;
		Utils::Log(LOG_DEBUG, "Collecting VLANs...");

		if (str_starts_with($sSysObjectID, '.1.3.6.1.4.1.3375.2.1.3.4')) {
			$aVLANs = static::LoadF5VLANs($oSNMP);
		} else {
			$aVLANs = static::LoadDot1qVLANS($oSNMP);
		}

		Utils::Log(LOG_DEBUG, sprintf('%d VLANs collected', count($aVLANs)));
		return $aVLANs;
	}


	/**
	 * Lookup VLANs using Q-BRIDGE-MIB tables
	 * @param SNMP $oSNMP
	 * @return array
	 */
	protected static function LoadDot1qVLANS(SNMP $oSNMP): array
	{
		$aVLANs = [];

		$dot1dBasePortIfIndex = @$oSNMP->walk('.1.3.6.1.2.1.17.1.4.1.2', true);
		$dot1qVlanCurrentEgressPorts = @$oSNMP->walk('.1.3.6.1.2.1.17.7.1.4.2.1.4', true);
		$dot1qVlanCurrentUntaggedPorts = @$oSNMP->walk('.1.3.6.1.2.1.17.7.1.4.2.1.5', true);
		$dot1qVlanStaticName = @$oSNMP->walk('.1.3.6.1.2.1.17.7.1.4.3.1.1', true);
		$dot1qVlanStaticEgressPorts = @$oSNMP->walk('.1.3.6.1.2.1.17.7.1.4.3.1.2', true);
		$dot1qVlanStaticUntaggedPorts = @$oSNMP->walk('1.3.6.1.2.1.17.7.1.4.3.1.4', true);

		if ($dot1qVlanStaticName !== false) foreach ($dot1qVlanStaticName as $iTag => $sVLAN) {
			$aVLANs[$iTag] = [
				'name' => ($sVLAN != $iTag) ? $sVLAN : '',
				'interfaces_list' => [],
				'untagged_interfaces_list' => [],
			];
		}

		if ($dot1qVlanStaticEgressPorts !== false) foreach ($dot1qVlanStaticEgressPorts as $iTag => $sEgressPorts) {
			$aVLANs[$iTag]['interfaces_list'] = static::MapPortListToInterfaces($sEgressPorts, $dot1dBasePortIfIndex);
		}

		if ($dot1qVlanStaticUntaggedPorts !== false) foreach ($dot1qVlanStaticUntaggedPorts as $iTag => $sUntaggedPorts) {
			$aVLANs[$iTag]['untagged_interfaces_list'] = static::MapPortListToInterfaces($sUntaggedPorts, $dot1dBasePortIfIndex);
		}

		if ($dot1qVlanCurrentEgressPorts !== false) foreach ($dot1qVlanCurrentEgressPorts as $sCurrentEntry => $sEgressPorts) {
			$iTag = (int) explode('.', $sCurrentEntry)[1];
			if (!isset($aVLANs[$iTag]['interfaces_list'])) $aVLANs[$iTag]['interfaces_list'] = [];
			$aVLANs[$iTag]['interfaces_list'] += static::MapPortListToInterfaces($sEgressPorts, $dot1dBasePortIfIndex);
		}

		if ($dot1qVlanCurrentUntaggedPorts !== false) foreach ($dot1qVlanCurrentUntaggedPorts as $sCurrentEntry => $sUntaggedPorts) {
			$iTag = (int) explode('.', $sCurrentEntry)[1];
			if (!isset($aVLANs[$iTag]['untagged_interfaces_list'])) $aVLANs[$iTag]['untagged_interfaces_list'] = [];
			$aVLANs[$iTag]['untagged_interfaces_list'] += static::MapPortListToInterfaces($sUntaggedPorts, $dot1dBasePortIfIndex);
		}

		return $aVLANs;
	}

	/**
	 * Specific VLAN lookup for F5 BIG-IP devices
	 * @param SNMP $oSNMP
	 * @return array
	 */
	protected static function LoadF5VLANs(SNMP $oSNMP): array
	{
		$aVLANs = [];
		$aVLANTagLookup = [];

		$ifName = @$oSNMP->walk('.1.3.6.1.2.1.31.1.1.1.1', true);

		$sysVlanVname = @$oSNMP->walk('.1.3.6.1.4.1.3375.2.1.2.13.1.2.1.1', true);
		$sysVlanId = @$oSNMP->walk('.1.3.6.1.4.1.3375.2.1.2.13.1.2.1.2', true);
		$sysVlanMemberVmname = @$oSNMP->walk('.1.3.6.1.4.1.3375.2.1.2.13.2.2.1.1', true);
		$sysVlanMemberTagged = @$oSNMP->walk('.1.3.6.1.4.1.3375.2.1.2.13.2.2.1.3', true);

		if ($sysVlanId !== false) foreach ($sysVlanId as $sIndex => $iTag) {
			$aVLANs[$iTag] = [
				'name' => $sysVlanVname[$sIndex] ?? '',
				'interfaces_list' => [],
				'untagged_interfaces_list' => [],
			];
			$aVLANTagLookup[$sIndex] = $iTag;
		}

		if ($sysVlanMemberVmname !== false) foreach ($sysVlanMemberVmname as $sMemberIndex => $sName) {
			$iIfIndex = array_search($sName, $ifName, true);

			foreach ($aVLANTagLookup as $sTagIndex => $iTag) if (str_starts_with($sMemberIndex, $sTagIndex)) {
				$aVLANs[$iTag]['interfaces_list'][] = $iIfIndex;
				if ($sysVlanMemberTagged !== false && $sysVlanMemberTagged[$sMemberIndex] === 0)
					$aVLANs[$iTag]['untagged_interfaces_list'][] = $iIfIndex;
				break;
			}
		}

		return $aVLANs;
	}

	/**
	 * @param string $sPortList Octet string of port mappings
	 * @param array $dot1dBasePortIfIndex
	 * @return array
	 */
	protected static function MapPortListToInterfaces(string $sPortList, array $dot1dBasePortIfIndex): array
	{
		$aInterfaces = [];
		$iOffset = 0;
		foreach (unpack('C*', $sPortList) as $iPortList) {
			foreach ([128, 64, 32, 16, 8, 4, 2, 1] as $iBitIndex => $iBit) {
				if ($iPortList & $iBit){
					$iPortIndex = $iOffset + $iBitIndex + 1;
					if (isset($dot1dBasePortIfIndex[$iPortIndex])) $aInterfaces[$iPortIndex] = $dot1dBasePortIfIndex[$iPortIndex];
				}
			}
			$iOffset += 8;
		}
		
		return $aInterfaces;
	}
}
