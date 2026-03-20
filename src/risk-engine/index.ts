/**
 * Aegis Risk Engine - Main exports
 */

export { scanContractSource, scanBytecode, type ScanResult, type ScanFinding } from "./scanner.js";
export {
  simulateTransaction,
  simulateWithTrace,
  checkTokenSellability,
  fetchContractSource,
  type SimulationRequest,
  type SimulationResult,
  type TraceAnalysis,
  type TracedContract,
} from "./simulator.js";
export {
  traceTransaction,
  flattenCallTree,
  deduplicateAddresses,
  filterScanTargets,
  isWellKnown,
  WELL_KNOWN_CONTRACTS,
  type TraceRequest,
  type TraceResult,
  type TraceCall,
  type RawCallFrame,
} from "./tracer.js";
export { EXPLOIT_PATTERNS, type ExploitPattern } from "./patterns.js";
