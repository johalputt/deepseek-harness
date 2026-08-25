/**
 * Private-network destination blocking: the pure classifier table plus
 * real-socket provider coverage proving a loopback target is refused before
 * any connection exists, that hostname resolution participates (the
 * rebinding-shaped path), and that opting out restores ambient fetching.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import { AddressInfo } from 'node:net'
import { HttpFetchProvider } from '../src/provider.ts'
import { isPubliclyRoutableAddress } from '../src/private-net.ts'

const baseLimits = {
  maxUrlLength: 2048,
  maxResponseBytes: 5_000_000,
  maxBodyChars: 100_000,
  timeoutMs: 5_000,
  maxRedirects: 5,
  userAgent: 'ssrf-test-agent/1.0',
}

describe('publicly-routable classification', () => {
  it('accepts public unicast addresses', () => {
    expect(isPubliclyRoutableAddress('1.1.1.1')).toBe(true)
    expect(isPubliclyRoutableAddress('8.8.8.8')).toBe(true)
    expect(isPubliclyRoutableAddress('203.0.114.9')).toBe(true) // outside TEST-NET-3
    expect(isPubliclyRoutableAddress('2606:4700::1111')).toBe(true)
    expect(isPubliclyRoutableAddress('2001:4860:4860::8888')).toBe(true)
  })

  it.each([
    ['unspecified IPv4', '0.0.0.0'],
    ['10/8 private', '10.1.2.3'],
    ['127/8 loopback', '127.0.0.1'],
    ['169.254/16 link-local (cloud metadata)', '169.254.169.254'],
    ['172.16/12 private lower edge', '172.16.0.1'],
    ['172.16/12 private upper edge', '172.31.255.255'],
    ['192.168/16 private', '192.168.1.1'],
    ['100.64/10 carrier-grade NAT', '100.100.1.1'],
    ['198.18/15 benchmarking', '198.19.255.255'],
    ['TEST-NET-1 documentation', '192.0.2.55'],
    ['TEST-NET-2 documentation', '198.51.100.7'],
    ['TEST-NET-3 documentation', '203.0.113.9'],
    ['multicast', '224.0.0.251'],
    ['reserved high range', '240.0.0.1'],
    ['broadcast', '255.255.255.255'],
  ])('refuses %s', (_label, address) => {
    expect(isPubliclyRoutableAddress(address)).toBe(false)
  })

  it.each([
    ['IPv6 loopback', '::1'],
    ['IPv6 unspecified', '::'],
    ['unique-local fc00::/7', 'fd00::1'],
    ['link-local fe80::/10', 'fe80::1'],
    ['multicast ff00::/8', 'ff02::1'],
    ['documentation 2001:db8::/32', '2001:db8::5'],
    ['NAT64 translating to loopback', '64:ff9b::127.0.0.1'],
    ['NAT64 translating to RFC1918', '64:ff9b::a00:1'],
    ['6to4 embedding RFC1918', '2002:a00:1::'],
  ])('refuses %s', (_label, address) => {
    expect(isPubliclyRoutableAddress(address)).toBe(false)
  })

  it('judges IPv4-mapped IPv6 by its embedded IPv4 self', () => {
    expect(isPubliclyRoutableAddress('::ffff:127.0.0.1')).toBe(false)
    expect(isPubliclyRoutableAddress('::ffff:10.0.0.5')).toBe(false)
    expect(isPubliclyRoutableAddress('::ffff:8.8.8.8')).toBe(true)
    // Binary spelling of the same mapped prefix.
    expect(isPubliclyRoutableAddress('::ffff:7f00:1')).toBe(false)
  })

  it('fails closed on malformed addresses', () => {
    expect(isPubliclyRoutableAddress('not-an-ip')).toBe(false)
    expect(isPubliclyRoutableAddress('999.1.1.1')).toBe(false)
    expect(isPubliclyRoutableAddress('1.2.3')).toBe(false)
    // A dotted tail is legal only as the final component: `10.0.0.1::` would
    // otherwise parse as an unrelated public v6 address.
    expect(isPubliclyRoutableAddress('10.0.0.1::')).toBe(false)
    expect(isPubliclyRoutableAddress('1:2:3:4:5:6:7:8:9')).toBe(false)
    expect(isPubliclyRoutableAddress('::::')).toBe(false)
  })
})

describe('provider private-network enforcement', () => {
  let server: Server
  let base: string
  let connections = 0

  beforeEach(async () => {
    connections = 0
    server = createServer((_req: IncomingMessage, res: ServerResponse) => {
      res.writeHead(200, { 'content-type': 'text/plain' })
      res.end('reachable')
    })
    server.on('connection', () => { connections++ })
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
    const { port } = server.address() as AddressInfo
    base = `http://127.0.0.1:${port}`
  })

  afterEach(async () => {
    await new Promise<void>((resolve) => {
      server.close(() => { resolve() })
    })
  })

  it('refuses a loopback literal with WEB_PRIVATE_NETWORK and opens no connection', async () => {
    const provider = new HttpFetchProvider({ ...baseLimits, blockPrivateNetworks: true })
    await expect(provider.fetch({ url: base }))
      .rejects.toThrow(expect.objectContaining({ code: 'WEB_PRIVATE_NETWORK' }))
    // The refusal happened in-process: no TCP connection to the refused
    // destination ever existed, which is what makes this an SSRF control.
    expect(connections).toBe(0)
  })

  it('refuses a hostname whose resolution lands non-public (the rebinding shape)', async () => {
    const provider = new HttpFetchProvider({ ...baseLimits, blockPrivateNetworks: true })
    const localUrl = new URL(base)
    localUrl.hostname = 'localhost'
    await expect(provider.fetch({ url: localUrl.toString() }))
      .rejects.toThrow(expect.objectContaining({ code: 'WEB_PRIVATE_NETWORK' }))
    expect(connections).toBe(0)
  }, 20_000)

  it('re-refuses every redirect hop under blocking', async () => {
    // Both hops are loopback, so with blocking on the FIRST hop already
    // fails; this pins that per-hop pre-flighting runs inside followAndRead,
    // not only on the initial URL.
    const provider = new HttpFetchProvider({ ...baseLimits, blockPrivateNetworks: true })
    await expect(provider.fetch({ url: `${base}/start` }))
      .rejects.toThrow(expect.objectContaining({ code: 'WEB_PRIVATE_NETWORK' }))
    expect(connections).toBe(0)
  })

  it('restores ambient fetching when the deployment opts out', async () => {
    const provider = new HttpFetchProvider({ ...baseLimits, blockPrivateNetworks: false })
    const result = await provider.fetch({ url: base })
    expect(result.statusCode).toBe(200)
    expect(result.body).toEqual({ kind: 'text', content: 'reachable' })
  })
})
