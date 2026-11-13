/**
 * Policy content hashes use the same reference-profile canonical JSON as receipts.
 * The implementation lives in adap-receipt so integer-like key order cannot drift.
 */
export { canonicalJson as canonicalJsonStringify } from 'adap-receipt'
