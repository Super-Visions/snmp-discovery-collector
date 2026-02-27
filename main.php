<?php
/**
 * @copyright 2024-2026 Super-Visions BVBA
 * @license http://opensource.org/licenses/AGPL-3.0
 * @noinspection PhpUnhandledExceptionInspection
 */

require_once(__DIR__.'/vendor/autoload.php');
require_once(__DIR__.'/src/SnmpCredentials.class.inc.php');
require_once(__DIR__.'/src/SnmpCollectionPlan.class.inc.php');
require_once(__DIR__.'/src/SnmpCollector.class.inc.php');
require_once(__DIR__.'/src/SnmpDiscoveryCollector.class.inc.php');
require_once(__DIR__.'/src/SnmpInterfaceCollector.class.inc.php');
require_once(__DIR__.'/src/IOSVersionCollector.class.inc.php');
require_once(__DIR__.'/src/ModelCollector.class.inc.php');

Orchestrator::AddRequirement('8.1');
Orchestrator::AddRequirement('8.1', 'snmp');

Orchestrator::UseCollectionPlan(SnmpCollectionPlan::class);
