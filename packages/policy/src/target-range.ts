export type TargetClass =
  | "public"
  | "private"
  | "carrier-grade"
  | "loopback"
  | "link-local"
  | "multicast"
  | "unspecified"
  | "broadcast"
  | "reserved";

export function classifyTargetRange(range: string): TargetClass {
  const mapping: Record<string, TargetClass> = {
    unicast: "public",
    private: "private",
    uniqueLocal: "private",
    carrierGradeNat: "carrier-grade",
    loopback: "loopback",
    linkLocal: "link-local",
    multicast: "multicast",
    unspecified: "unspecified",
    broadcast: "broadcast",
    reserved: "reserved"
  };
  return mapping[range] ?? "reserved";
}
