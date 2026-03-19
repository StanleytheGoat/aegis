/**
 * Aegis Risk Engine — Main exports
 */

export { scanContractSource, scanBytecode, type ScanResult, type ScanFinding } from "./scanner.js";
export { simulateTransaction, checkTokenSellability, type SimulationRequest, type SimulationResult } from "./simulator.js";
export { EXPLOIT_PATTERNS, type ExploitPattern } from "./patterns.js";
