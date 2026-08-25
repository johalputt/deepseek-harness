/**
 * Private-network destination blocking for the local HTTP(S) fetch provider —
 * the pure, network-free half. A hostname is fetchable only when every
 * address it resolves to is publicly routable: one non-public answer rejects
 * the whole name, so an attacker-controlled authoritative server cannot mix a
 * public record in front of a private one. The provider composes this module
 * twice per hop — a pre-flight resolution that fails fast with
 * `WEB_PRIVATE_NETWORK`, and the connect-time `lookup` inside the undici
 * dispatcher, which re-validates whatever address the socket actually opens,
 * closing the resolve-then-connect gap (DNS rebinding / TOCTOU).
 *
 * @module @deepseek-ai/dsh-web-fetch-http/private-net
 */

import { lookup } from 'node:dns/promises'
import { WebError } from '@deepseek-ai/dsh-web'

/** One parsed IPv6 address as eight 16-bit groups (`::` already expanded). */
type Ipv6Groups = readonly [number, number, number, number, number, number, number, number]

/** Parse dotted-decimal IPv4 into its 32-bit value, or undefined when malformed. */
function parseIpv4(address: string): number | undefined {
  const parts = address.split('.')
  if (parts.length !== 4) return undefined
  let value = 0
  for (const part of parts) {
    // Decimal only: WHATWG URL parsing rejects octal/hex spellings before we
    // ever see them, and accepting them here would disagree with the parser.
    if (!/^\d{1,3}$/.test(part)) return undefined
    const octet = Number(part)
    if (octet > 255) return undefined
    value = value * 256 + octet
  }
  return value
}

/** Parse textual IPv4-in-IPv6 tail (e.g. `192.0.2.1`) into two groups, or undefined. */
function parseIpv4TailAsGroups(tail: string): [number, number] | undefined {
  const value = parseIpv4(tail)
  if (value === undefined) return undefined
  return [value >>> 16, value & 0xffff]
}

/**
 * Expand a textual IPv6 address into its eight 16-bit groups.
 * Accepts `::` compression, a single embedded dotted-decimal tail, and zone
 * stripping (`%eth0`). Returns undefined for anything malformed — callers
 * treat unparsable addresses as non-public (fail closed).
 */
export function parseIpv6(input: string): Ipv6Groups | undefined {
  let text = input
  const zone = text.indexOf('%')
  if (zone !== -1) text = text.slice(0, zone)
  if (text.length === 0) return undefined

  let head: string[]
  let tail: string[]
  const compression = text.indexOf('::')
  if (compression !== -1) {
    // At most one `::`; a second occurrence makes the address ambiguous.
    if (text.indexOf('::', compression + 1) !== -1) return undefined
    head = text.slice(0, compression).split(':')
    tail = text.slice(compression + 2).split(':')
    if (head.length === 1 && head[0] === '') head = []
    if (tail.length === 1 && tail[0] === '') tail = []
  } else {
    head = text.split(':')
    tail = []
  }
  if (head.length + tail.length > 8) return undefined

  const parts = [...head, ...tail]
  const groups: number[] = []
  // An embedded dotted-decimal tail is legal only as the very last component,
  // and under `::` compression only AFTER the marker (`fe80::1.2.3.4`,
  // `::ffff:10.0.0.1`). Accepting it elsewhere (e.g. `10.0.0.1::`, whose
  // groups would otherwise classify as an unrelated public v6 address)
  // instead of failing closed would open a classification bypass.
  for (const [index, part] of parts.entries()) {
    if (part.includes('.')) {
      const afterCompression = compression !== -1 && index >= head.length
      if ((compression === -1 || afterCompression) && index === parts.length - 1) {
        const converted = parseIpv4TailAsGroups(part)
        if (converted === undefined) return undefined
        groups.push(converted[0], converted[1])
        continue
      }
      return undefined
    }
    if (!/^[0-9a-fA-F]{1,4}$/.test(part)) return undefined
    groups.push(Number.parseInt(part, 16))
  }

  if (compression !== -1) {
    const missing = 8 - groups.length
    if (missing < 0) return undefined
    groups.splice(head.length, 0, ...Array.from({ length: missing }, () => 0))
  }
  // The length check above is what makes this tuple view sound; this is the
  // one place a plain array is re-typed to the function's parsed-result shape.
  if (groups.length !== 8) return undefined
  return groups as unknown as Ipv6Groups
}

/** Whether one 32-bit IPv4 value is globally routable unicast space. */
export function isPubliclyRoutableIpv4(value: number): boolean {
  const first = value >>> 24
  const second = (value >>> 16) & 0xff
  // 0/8 "this network"; 10/8 private; 127/8 loopback.
  if (first === 0 || first === 10 || first === 127) return false
  // 100.64/10 carrier-grade NAT; 169.254/16 link-local (cloud metadata lives here).
  if (first === 100 && second >= 64 && second <= 127) return false
  if (first === 169 && second === 254) return false
  // 172.16/12 private.
  if (first === 172 && second >= 16 && second <= 31) return false
  // 192.0.0/24 (IETF protocol assignments), 192.0.2/24 TEST-NET-1,
  // 192.88.99/24 deprecated 6to4 relay anycast, 192.168/16 private.
  if (first === 192) {
    if (second === 0) return false // covers .0.0/24 and .0.2/24
    if (second === 88 && ((value >>> 8) & 0xff) === 99) return false
    if (second === 168) return false
  }
  // 198.18/15 benchmarking; 198.51.100/24 TEST-NET-2; 203.0.113/24 TEST-NET-3.
  if (first === 198 && (second === 18 || second === 19)) return false
  if (first === 198 && second === 51 && ((value >>> 8) & 0xff) === 100) return false
  if (first === 203 && second === 0 && ((value >>> 8) & 0xff) === 113) return false
  // 224/4 multicast; 240/4 reserved incl. the 255.255.255.255 broadcast.
  if (first >= 224) return false
  return true
}

/**
 * Whether one IP-address string (IPv4 or IPv6, brackets stripped by the URL
 * parser) is publicly routable. Unparsable input fails closed. Embedded-IPv4
 * forms are unwrapped and judged by their IPv4 self, so `::ffff:10.0.0.5`,
 * `2002:0a00:0001::` (6to4), and `64:ff9b::a00:1` (NAT64) are all refused
 * exactly when their embedded IPv4 address would be.
 */
export function isPubliclyRoutableAddress(address: string): boolean {
  if (address.includes(':')) {
    const groups = parseIpv6(address)
    if (groups === undefined) return false
    // Unspecified (::) and loopback (::1).
    if (groups.every(group => group === 0)) return false
    if (groups[0] === 0 && groups[1] === 0 && groups[2] === 0 && groups[3] === 0
      && groups[4] === 0 && groups[5] === 0 && groups[6] === 0 && groups[7] === 1) return false
    const low32 = (groups[6] << 16) | groups[7]
    // IPv4-mapped ::ffff:0:0/96.
    if (groups[0] === 0 && groups[1] === 0 && groups[2] === 0 && groups[3] === 0
      && groups[4] === 0 && groups[5] === 0xffff) return isPubliclyRoutableIpv4(low32)
    // NAT64 64:ff9b::/96 translates to the embedded IPv4 host.
    if (groups[0] === 0x64 && groups[1] === 0xff9b
      && groups[2] === 0 && groups[3] === 0 && groups[4] === 0 && groups[5] === 0) {
      return isPubliclyRoutableIpv4(low32)
    }
    // 6to4 2002::/16 carries the IPv4 relay target in the next 32 bits.
    if (groups[0] === 0x2002) return isPubliclyRoutableIpv4((groups[1] << 16) | groups[2])
    // Unique-local fc00::/7, link-local fe80::/10, multicast ff00::/8,
    // documentation 2001:db8::/32.
    if ((groups[0] & 0xfe00) === 0xfc00) return false
    if ((groups[0] & 0xffc0) === 0xfe80) return false
    if ((groups[0] & 0xff00) === 0xff00) return false
    if (groups[0] === 0x2001 && groups[1] === 0xdb8) return false
    return true
  }
  const value = parseIpv4(address)
  return value !== undefined && isPubliclyRoutableIpv4(value)
}

interface LookupAnswer {
  address: string
}

/**
 * Resolve `hostname` through the platform resolver and require EVERY answer
 * to be publicly routable. Empty resolution or any non-public address throws
 * {@link WebError} `WEB_PRIVATE_NETWORK`. This is the pre-flight half of the
 * per-hop check; the dispatcher's connect-time lookup remains the authority
 * against resolution changes between this call and socket open.
 * @param hostname - the hop hostname from a validated URL (no brackets).
 */
export async function assertPublicHost(hostname: string): Promise<void> {
  const literalAddress = hostname.startsWith('[') && hostname.endsWith(']')
    ? hostname.slice(1, -1)
    : hostname
  let answers: LookupAnswer[]
  try {
    answers = await lookup(literalAddress, { all: true, order: 'verbatim' })
  } catch (error: unknown) {
    throw new WebError(`host "${hostname}" could not be resolved`, 'WEB_INVALID_URL', { cause: error })
  }
  const offending = answers.find(answer => !isPubliclyRoutableAddress(answer.address))
  if (offending !== undefined) {
    throw new WebError(
      `"${hostname}" resolves to the non-public address ${offending.address}; `
      + 'web-fetch-http refuses private-network destinations when blockPrivateNetworks is enabled',
      'WEB_PRIVATE_NETWORK',
    )
  }
}
