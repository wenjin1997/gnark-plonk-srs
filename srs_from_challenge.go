package main

import (
	"fmt"
	"io"
	"os"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
)

func main() {
	challenge, _ := os.Open("challenge_19")
	defer challenge.Close()

	challenge.Seek(64, io.SeekStart) // Skip hash

	// Read the maximum number of G1 points we need (2^27 + 3)
	N := 27
	maxSize := (1 << N) + 3

	// Store all G1 points in memory
	g1 := make([]bls12381.G1Affine, maxSize)
	for i := 0; i < maxSize; i++ {
		var point bls12381.G1Affine
		xBytes := make([]byte, 48)
		yBytes := make([]byte, 48)

		io.ReadFull(challenge, xBytes)
		io.ReadFull(challenge, yBytes)

		point.X.SetBytes(xBytes)
		point.Y.SetBytes(yBytes)

		g1[i] = point

		if i%1000000 == 0 && i > 0 {
			fmt.Printf("  Read %d G1 points...\n", i)
		}
	}
	fmt.Printf("✓ Read all %d G1 points\n", maxSize)

	// Skip to G2 section
	currentPos, _ := challenge.Seek(0, io.SeekCurrent)
	challenge.Seek(currentPos+(int64(1<<28-1)-int64(maxSize))*96, io.SeekStart)

	// Read G2 points
	var g2 [2]bls12381.G2Affine
	var lines [2][2][63]bls12381.LineEvaluationAff
	for i := 0; i < 2; i++ {
		var point bls12381.G2Affine
		xa1Bytes := make([]byte, 48)
		xa0Bytes := make([]byte, 48)
		ya1Bytes := make([]byte, 48)
		ya0Bytes := make([]byte, 48)

		io.ReadFull(challenge, xa1Bytes)
		io.ReadFull(challenge, xa0Bytes)
		io.ReadFull(challenge, ya1Bytes)
		io.ReadFull(challenge, ya0Bytes)

		point.X.A1.SetBytes(xa1Bytes)
		point.X.A0.SetBytes(xa0Bytes)
		point.Y.A1.SetBytes(ya1Bytes)
		point.Y.A0.SetBytes(ya0Bytes)

		g2[i] = point
		lines[i] = bls12381.PrecomputeLines(g2[i]) // must do it, otherwise not sound
	}

	for n := 0; n <= N; n += 1 {
		sizeLagrange := 1 << n
		sizeCanonical := sizeLagrange + 3

		// Generate canonical form SRS
		outputPath := fmt.Sprintf("srs_%d.srs", n)
		fmt.Printf("Generating %s         (2^%d+3 = %d points)...", outputPath, n, sizeCanonical)

		var srs kzg.SRS
		srs.Pk.G1 = g1[:sizeCanonical]
		srs.Vk.G1 = g1[0]
		srs.Vk.G2 = g2
		srs.Vk.Lines = lines

		out, _ := os.Create(outputPath)
		srs.WriteTo(out)
		out.Close()
		fileInfo, _ := os.Stat(outputPath)
		fmt.Printf(" ✓ (%.2f MB)\n", float64(fileInfo.Size())/(1024*1024))

		// Generate Lagrange form SRS
		outputPath = fmt.Sprintf("srsLagrange_%d.srs", n)
		fmt.Printf("Generating %s (2^%d   = %d points)...", outputPath, n, sizeLagrange)

		var srsLagrange kzg.SRS
		srsLagrange.Pk.G1, _ = kzg.ToLagrangeG1(g1[:sizeLagrange])
		srsLagrange.Vk = srs.Vk

		out, _ = os.Create(outputPath)
		srsLagrange.WriteTo(out)
		out.Close()
		fileInfo, _ = os.Stat(outputPath)
		fmt.Printf(" ✓ (%.2f MB)\n", float64(fileInfo.Size())/(1024*1024))
	}
}
