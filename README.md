# GNARK PLONK SRS Extractor (BLS12-381)

Extract gnark PLONK-compatible SRS from Filecoin's trusted setup Phase 1.

## Overview

This tool extracts Structured Reference Strings (SRS) from Filecoin's BLS12-381 trusted setup [Phase 1](https://github.com/filecoin-project/phase2-attestations?tab=readme-ov-file#phase1) for use with gnark's PLONK implementation.

## Prerequisites

- Download `challenge_19` from http://trusted-setup.filecoin.io/phase1/challenge_19
- Install Go 1.19+
- Install gnark dependencies:
  ```bash
  go get github.com/consensys/gnark-crypto
  go get github.com/consensys/gnark
  ```

## Usage

### Generate SRS Files

```bash
go run srs_from_challenge.go
```

This generates:
- **Canonical SRS**: `srs_0.srs` to `srs_27.srs` (2^n + 3 G1 points each)
- **Lagrange SRS**: `srsLagrange_0.srs` to `srsLagrange_27.srs` (2^n G1 points each)

### Example Usage

```bash
go run example.go
```

Demonstrates PLONK proving and verification using the extracted SRS.

## File Structure

- `srs_from_challenge.go` - Extracts SRS from challenge_19
- `example.go` - Example PLONK circuit using extracted SRS

## Technical Details

The challenge_19 file structure:
- 64 bytes: Blake2b hash
- (2^28-1) × 96 bytes: tau_powers_g1 (τ^i in G1, canonical form)
- 2^27 × 192 bytes: tau_powers_g2 (τ^i in G2)
- Additional Groth16-specific data (not used by PLONK)

Generated SRS file structure (gnark kzg.SRS format):
```go
type SRS struct {
    Pk ProvingKey {
        G1 []G1Affine  // [G₁, [τ]G₁, [τ²]G₁, ...] canonical or Lagrange
    }
    Vk VerifyingKey {
        G2    [2]G2Affine  // [G₂, [τ]G₂]
        G1    G1Affine     // Generator G₁
        Lines [2][2][63]LineEvaluationAff  // Precomputed pairing lines
    }
}
```

### SRS Size Requirements for Circuits

For a gnark circuit, `sizeSystem = nbConstraints + nbPublic`:
- **Canonical SRS**: size ≥ NextPowerOfTwo(sizeSystem) + 3
- **Lagrange SRS**: size = NextPowerOfTwo(sizeSystem) (must be exact)

Example: The `example.go` circuit has 2160 constraints + 2 public variables = 2162 sizeSystem
- NextPowerOfTwo(2162) = 4096 (2^12)
- **Lagrange SRS**: Must use `srsLagrange_12.srs` (exactly 4096 points)
- **Canonical SRS**: Can use `srs_12.srs` (4099 points), `srs_13.srs`, or any larger file

## License

Apache 2.0