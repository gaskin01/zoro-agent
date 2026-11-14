declare module "snarkjs" {
  export namespace groth16 {
    function fullProve(
      input: Record<string, unknown>,
      wasmPath: string,
      zkeyPath: string,
    ): Promise<{ proof: unknown; publicSignals: string[] }>;
    function verify(vk: unknown, publicSignals: string[], proof: unknown): Promise<boolean>;
  }
  export namespace zKey {
    function exportVerificationKey(zkeyPath: string): Promise<unknown>;
  }
}
