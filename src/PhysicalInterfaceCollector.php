<?php

class PhysicalInterfaceCollector extends SnmpInterfaceCollector
{
	/**
	 * Retrieve and prepare interfaces discovered by SnmpDiscoveryCollector
	 * @return true
	 */
	public function Prepare()
	{
		$this->aInterfaces = SnmpDiscoveryCollector::$aDiscoveredInterfaces['physicalinterface_list'];

		return parent::Prepare();
	}

	/**
	 * Do actual device lookup
	 * @inheritDoc
	 */
	public function ProcessLineBeforeSynchro(&$aLineData, $iLineIndex)
	{
		$this->oDeviceLookup->Lookup($aLineData, static::DeviceLookupFields, 'connectableci_id', $iLineIndex);
		parent::ProcessLineBeforeSynchro($aLineData, $iLineIndex);
	}
}
