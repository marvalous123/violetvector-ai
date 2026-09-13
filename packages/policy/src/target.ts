import ipaddr from "ipaddr.js";
import { classifyTargetRange } from "./target-range.js";
import type { TargetClass } from "./target-range.js";

export type { TargetClass } from "./target-range.js";

export interface CanonicalTarget {
  address: string;
  family: "ipv4" | "ipv6";
  classification: TargetClass;
}

export class TargetParseError extends Error {
  constructor(
    public readonly code:
      | "TARGET_NOT_IP"
      | "TARGET_CIDR_FORBIDDEN"
      | "TARGET_ALTERNATE_ENCODING"
      | "TARGET_MAPPED_IPV6_FORBIDDEN",
    message: string
  ) {
    super(message);
    this.name = "TargetParseError";
  }
}

function parseStrictIpv4(value: string): ipaddr.IPv4 | undefined {
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)) return undefined;
  const octets = value.split(".");
  if (octets.some((octet) => (octet.length > 1 && octet.startsWith("0")) || Number(octet) > 255)) {
    throw new TargetParseError("TARGET_ALTERNATE_ENCODING", "IPv4 must use unpadded dotted-decimal notation");
  }
  return ipaddr.IPv4.parse(value);
}

export function canonicalizeTarget(input: string): CanonicalTarget {
  if (input.includes("/")) {
    throw new TargetParseError("TARGET_CIDR_FORBIDDEN", "CIDR targets are not supported in the MVP");
  }
  if (input !== input.trim()) {
    throw new TargetParseError("TARGET_ALTERNATE_ENCODING", "Target must not contain surrounding whitespace");
  }

  const ipv4 = parseStrictIpv4(input);
  if (ipv4) {
    return {
      address: ipv4.toString(),
      family: "ipv4",
      classification: classifyTargetRange(ipv4.range())
    };
  }

  if (!input.includes(":")) {
    throw new TargetParseError("TARGET_NOT_IP", "Only literal IP targets are supported in the MVP");
  }

  let address: ipaddr.IPv6;
  try {
    address = ipaddr.IPv6.parse(input);
  } catch {
    throw new TargetParseError("TARGET_NOT_IP", "Target is not a valid IP literal");
  }
  if (address.isIPv4MappedAddress()) {
    throw new TargetParseError("TARGET_MAPPED_IPV6_FORBIDDEN", "IPv4-mapped IPv6 is not supported in the MVP");
  }
  return {
    address: address.toNormalizedString(),
    family: "ipv6",
    classification: classifyTargetRange(address.range())
  };
}
