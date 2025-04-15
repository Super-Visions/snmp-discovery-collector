<?php

abstract class SnmpInterfaceCollector extends SnmpCollector
{
	/** @var array List of prepared interfaces to be synchronised */
	protected array $aInterfaces = [];
	/** @var LookupTable Lookup table for NetworkDevice */
	protected LookupTable $oDeviceLookup;
	/** @var string[] Fields to be used for NetworkDevice lookup */
	public const DeviceLookupFields = ['org_id', 'managementip_id', 'snmpcredentials_id'];
	/** @var array<string, int> The position of each lookup field in the current CSV file */
	protected array $aLookupFieldPos = [];

	/**
	 * @return array|false
	 */
	public function Fetch()
	{
		$aInterface = current($this->aInterfaces);
		next($this->aInterfaces);
		return $aInterface;
	}

	/**
	 * Allow additional fields to look up the NetworkDevice
	 * @param string $sHeader
	 * @return bool
	 */
	public function HeaderIsAllowed(string $sHeader): bool
	{
		if (in_array($sHeader, static::DeviceLookupFields)) return true;

		return parent::HeaderIsAllowed($sHeader);
	}

	/**
	 * Interface collectors need processing to map correct NetworkDevice
	 * @return true
	 */
	public function MustProcessBeforeSynchro()
	{
		return true;
	}

	/**
	 * Init needed lookup tables
	 * @return void
	 */
	public function InitProcessBeforeSynchro()
	{
		$this->oDeviceLookup = new LookupTable('SELECT NetworkDevice', static::DeviceLookupFields);
	}

	/**
	 * Keep track of the position of the lookup fields and remove them from the CSV line
	 * @param array $aLineData The current CSV line data
	 * @param int $iLineIndex Index of the line in the current CSV file
	 * @return void
	 */
	public function ProcessLineBeforeSynchro(&$aLineData, $iLineIndex)
	{
		if ($iLineIndex == 0) {
			foreach ($aLineData as $iPos => $sField) {
				if (in_array($sField, static::DeviceLookupFields)) {
					$this->aLookupFieldPos[$sField] = $iPos;
				}
			}
		}

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
	public static function CollectInterfaces(SNMP $oSNMP)
	{
		$aInterfaces = [
			'physicalinterface_list' => [],
			'networkdevicevirtualinterfaces_list' => [],
			'aggregatelinks_list' => [],
		];

		// Load from ifTable
		$ifDescr = @$oSNMP->walk('.1.3.6.1.2.1.2.2.1.2', true);
		$ifType = @$oSNMP->walk('.1.3.6.1.2.1.2.2.1.3', true);
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
				'name' => $ifDescr[$iIfIndex],
				'comment' => '',
				'interfacespeed_id' => $ifSpeed[$iIfIndex],
			];

			if (!empty($ifName[$iIfIndex])) {
				$aInterface['name'] = $ifName[$iIfIndex];

				if ($ifName[$iIfIndex] != $ifDescr[$iIfIndex]) $aInterface['comment'] = $ifDescr[$iIfIndex].PHP_EOL;
			}

			if (isset($ifPhysAddress[$iIfIndex])) $aInterface['macaddress'] = vsprintf('%s:%s:%s:%s:%s:%s', str_split(bin2hex($ifPhysAddress[$iIfIndex]), 2));
			if (isset($ifAdminStatus[$iIfIndex])) $aInterface['status'] = $ifAdminStatus[$iIfIndex];
			if (isset($ifHighSpeed[$iIfIndex])) $aInterface['interfacespeed_id'] = $ifHighSpeed[$iIfIndex] * 1000000;
			if (isset($ifAlias[$iIfIndex])) $aInterface['comment'] .= $ifAlias[$iIfIndex];

			switch ($iIfType) {
				case 6: // ethernet-csmacd
					$aInterface['connectableci_id'] = null;
					$aInterfaces['physicalinterface_list'][] = $aInterface;
					break;
				case 161: // ieee8023adLag
					$aInterface['functionalci_id'] = null;
					$aInterfaces['aggregatelinks_list'][] = $aInterface;
					break;
				default:
					$aInterface['networkdevice_id'] = null;
					$aInterfaces['networkdevicevirtualinterfaces_list'][] = $aInterface;
					break;
			}
		}

		return $aInterfaces;
	}
}
