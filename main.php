<?php
/**
 * @copyright 2024-2025 Super-Visions BVBA
 * @license http://opensource.org/licenses/AGPL-3.0
 * @noinspection PhpUnhandledExceptionInspection
 */

require_once(__DIR__.'/vendor/autoload.php');
require_once(__DIR__.'/src/SnmpCredentials.class.inc.php');
require_once(__DIR__.'/src/SnmpCollector.php');
require_once(__DIR__.'/src/SnmpDiscoveryCollector.class.inc.php');
require_once(__DIR__.'/src/SnmpInterfaceCollector.php');
require_once(__DIR__.'/src/PhysicalInterfaceCollector.php');

Orchestrator::AddRequirement('8.1');
Orchestrator::AddRequirement('8.1', 'snmp');
Orchestrator::AddCollector(1, SnmpDiscoveryCollector::class);
Orchestrator::AddCollector(2, PhysicalInterfaceCollector::class);
