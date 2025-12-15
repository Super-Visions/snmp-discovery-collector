<?php

abstract class SnmpInterfaceCollector extends SnmpCollector
{
	/** @var LookupTable Lookup table for NetworkDevice */
	protected LookupTable $oDeviceLookup;
	/** @var string[] Fields to be used for NetworkDevice lookup */
	public const DeviceLookupFields = ['org_id', 'managementip_id', 'snmpcredentials_id'];
	/** @var array<string, int> The position of each lookup field in the current CSV file */
	protected array $aLookupFieldPos = [];

	/**
	 * Retrieve and prepare interfaces discovered by SnmpDiscoveryCollector
	 * @return true
	 */
	public function Prepare(): bool
	{
		$this->aData = SnmpDiscoveryCollector::$aDiscoveredInterfaces[static::InterfaceList];

		return parent::Prepare();
	}

	/**
	 * Allow additional fields to look up the NetworkDevice
	 * @param string $sHeader
	 * @return bool
	 */
	public function HeaderIsAllowed($sHeader)
	{
		if (in_array($sHeader, static::DeviceLookupFields)) return true;

		return parent::HeaderIsAllowed($sHeader);
	}

	/**
	 * Interface collectors need processing to map correct NetworkDevice
	 * @return true
	 */
	public function MustProcessBeforeSynchro(): bool
	{
		return true;
	}

	/**
	 * Init needed lookup tables
	 * @return void
	 */
	public function InitProcessBeforeSynchro(): void
	{
		$this->oDeviceLookup = new LookupTable('SELECT NetworkDevice', static::DeviceLookupFields);
	}

	/**
	 * Keep track of the position of the lookup fields and remove them from the CSV line
	 * @param array $aLineData The current CSV line data
	 * @param int $iLineIndex Index of the line in the current CSV file
	 * @return void
	 */
	public function ProcessLineBeforeSynchro(&$aLineData, $iLineIndex): void
	{
		if ($iLineIndex == 0) {
			foreach ($aLineData as $iPos => $sField) {
				if (in_array($sField, static::DeviceLookupFields)) {
					$this->aLookupFieldPos[$sField] = $iPos;
				}
			}
		}

		$this->oDeviceLookup->Lookup($aLineData, static::DeviceLookupFields, static::DeviceDestField, $iLineIndex);

		// Lookup field not needed anymore after it has been used for preprocessing
		foreach ($this->aLookupFieldPos as $iPos) unset($aLineData[$iPos]);
	}

	/**
	 * Collect device interfaces via SNMP
	 * @param SNMP $oSNMP
	 * @return array{
	 *     physicalinterface_list: array,
	 *     networkdevicevirtualinterfaces_list: array,
	 *     aggregatelinks_list: array,
	 * }
	 * @throws Exception
	 */
	public static function CollectInterfaces(SNMP $oSNMP): array
	{
		$aInterfaces = [
			PhysicalInterfaceCollector::InterfaceList => [],
			VirtualInterfaceCollector::InterfaceList => [],
			AggregateLinkCollector::InterfaceList => [],
		];

		if (!filter_var(Utils::GetConfigurationValue('collect_interfaces', false), FILTER_VALIDATE_BOOLEAN)) return $aInterfaces;
		Utils::Log(LOG_DEBUG, "Collecting interfaces...");

		// Load from ifTable
		$ifDescr = @$oSNMP->walk('.1.3.6.1.2.1.2.2.1.2', true);
		$ifType = @$oSNMP->walk('.1.3.6.1.2.1.2.2.1.3', true);
		$ifMtu = @$oSNMP->walk('.1.3.6.1.2.1.2.2.1.4', true);
		$ifSpeed = @$oSNMP->walk('.1.3.6.1.2.1.2.2.1.5', true);
		$ifPhysAddress = @$oSNMP->walk('.1.3.6.1.2.1.2.2.1.6', true);
		$ifAdminStatus = @$oSNMP->walk('.1.3.6.1.2.1.2.2.1.7', true);

		// Load from ifXTable
		$ifName = @$oSNMP->walk('.1.3.6.1.2.1.31.1.1.1.1', true);
		$ifHighSpeed = @$oSNMP->walk('.1.3.6.1.2.1.31.1.1.1.15', true);
		$ifAlias = @$oSNMP->walk('.1.3.6.1.2.1.31.1.1.1.18', true);

		if ($ifType !== false) foreach ($ifType as $iIfIndex => $iIfType) {
			$aInterface = [
				'primary_key' => $iIfIndex,
				'name' => null,
				'comment' => '',
				'macaddress' => null,
				'interfacespeed_id' => null,
				'layer2protocol_id' => null,
				'status' => null,
				'mtu' => null,
			];

			if (!empty($ifName[$iIfIndex])) {
				$aInterface['name'] = $ifName[$iIfIndex];

				if (isset($ifDescr[$iIfIndex]) && $ifName[$iIfIndex] != $ifDescr[$iIfIndex]) $aInterface['comment'] = $ifDescr[$iIfIndex].PHP_EOL;
			} elseif (!empty($ifDescr[$iIfIndex])) {
                $aInterface['name'] = $ifDescr[$iIfIndex];
            }

			if (isset($ifAdminStatus[$iIfIndex])) $aInterface['status'] = $ifAdminStatus[$iIfIndex];
			if (isset($ifPhysAddress[$iIfIndex]) && strlen($ifPhysAddress[$iIfIndex]) == 6)
				$aInterface['macaddress'] = vsprintf('%s:%s:%s:%s:%s:%s', str_split(bin2hex($ifPhysAddress[$iIfIndex]), 2));
			if (isset($ifHighSpeed[$iIfIndex])) $aInterface['interfacespeed_id'] = $ifHighSpeed[$iIfIndex] * 1000000;
			elseif (isset($ifSpeed[$iIfIndex])) $aInterface['interfacespeed_id'] = $ifSpeed[$iIfIndex];
			if (isset($ifAlias[$iIfIndex])) $aInterface['comment'] .= $ifAlias[$iIfIndex];
			if (isset($ifMtu[$iIfIndex])) $aInterface['mtu'] = $ifMtu[$iIfIndex];

			$aInterface['comment'] = mb_convert_encoding(trim($aInterface['comment']), 'UTF-8', ['UTF-8', 'ISO-8859-1', 'Windows-1252']);

			/**
			 * @see https://www.iana.org/assignments/ianaiftype-mib/ianaiftype-mib
			 */
			switch ($iIfType) {
				case 6: // ethernetCsmacd
					$aInterface[PhysicalInterfaceCollector::DeviceDestField] = null;
					$aInterface['layer2protocol_id'] = 'Ethernet';
					$aInterfaces[PhysicalInterfaceCollector::InterfaceList][] = $aInterface;
					break;
				case 161: // ieee8023adLag
					$aInterface[AggregateLinkCollector::DeviceDestField] = null;
					$aInterfaces[AggregateLinkCollector::InterfaceList][] = $aInterface;
					break;
				default:
					$aInterface[VirtualInterfaceCollector::DeviceDestField] = null;
					$aInterfaces[VirtualInterfaceCollector::InterfaceList][] = $aInterface;
					break;
			}
		}

		Utils::Log(LOG_DEBUG, sprintf('%d interfaces collected', array_reduce($aInterfaces, fn($c, $item) => $c + count($item))));
		return $aInterfaces;
	}
}

class PhysicalInterfaceCollector extends SnmpInterfaceCollector
{
	public const DeviceDestField = 'connectableci_id';
	public const InterfaceList = 'physicalinterface_list';
}

class VirtualInterfaceCollector extends SnmpInterfaceCollector
{
	public const DeviceDestField = 'networkdevice_id';
	public const InterfaceList = 'networkdevicevirtualinterfaces_list';
}

class AggregateLinkCollector extends SnmpInterfaceCollector
{
	public const DeviceDestField = 'functionalci_id';
	public const InterfaceList = 'aggregatelinks_list';
}
