// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package main

import (
	"fmt"
	"log"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend/cs/scs"

	"github.com/consensys/gnark/frontend"
)

// In this example we show how to use PLONK with KZG commitments. The circuit that is
// showed here is the same as in ../exponentiate.

// Circuit y == x**e
// only the bitSize least significant bits of e are used
type Circuit struct {
	// tagging a variable is optional
	// default uses variable name and secret visibility.
	X frontend.Variable `gnark:",public"`
	Y frontend.Variable `gnark:",public"`

	E frontend.Variable
}

// Define declares the circuit's constraints
// y == x**e
func (circuit *Circuit) Define(api frontend.API) error {

	// number of bits of exponent
	const bitSize = 4000

	// specify constraints
	output := frontend.Variable(1)
	bits := api.ToBinary(circuit.E, bitSize)

	for i := 0; i < len(bits); i++ {
		// api.Println(fmt.Sprintf("e[%d]", i), bits[i]) // we may print a variable for testing and / or debugging purposes

		if i != 0 {
			output = api.Mul(output, output)
		}
		multiply := api.Mul(output, circuit.X)
		output = api.Select(bits[len(bits)-1-i], multiply, output)

	}

	api.AssertIsEqual(circuit.Y, output)

	return nil
}

func main() {

	var circuit Circuit

	// // building the circuit...
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), scs.NewBuilder, &circuit)
	if err != nil {
		fmt.Println("circuit compilation error")
	}

	// Read SRS from local files instead of generating new ones
	fmt.Println("Reading SRS from local files...")

	// Read canonical SRS
	canonicalFile, err := os.Open("srs_20.srs")
	defer canonicalFile.Close()
	var srs kzg.SRS
	_, err = srs.ReadFrom(canonicalFile)
	fmt.Printf("Loaded canonical SRS with %d G1 points\n", len(srs.Pk.G1))

	// Read Lagrange SRS
	lagrangeFile, err := os.Open("srsLagrange_12.srs")
	defer lagrangeFile.Close()
	var srsLagrange kzg.SRS
	_, err = srsLagrange.ReadFrom(lagrangeFile)
	fmt.Printf("Loaded Lagrange SRS with %d G1 points\n", len(srsLagrange.Pk.G1))

	// Check if SRS sizes are sufficient for the circuit
	// canonical>=n+3, lagrange==n

	// Correct data: the proof passes
	{
		// Witnesses instantiation. Witness is known only by the prover,
		// while public w is a public data known by the verifier.
		var w Circuit
		w.X = 2
		w.E = 2
		w.Y = 4

		witnessFull, err := frontend.NewWitness(&w, ecc.BLS12_381.ScalarField())
		if err != nil {
			log.Fatal(err)
		}

		witnessPublic, err := frontend.NewWitness(&w, ecc.BLS12_381.ScalarField(), frontend.PublicOnly())
		if err != nil {
			log.Fatal(err)
		}

		// public data consists of the polynomials describing the constants involved
		// in the constraints, the polynomial describing the permutation ("grand
		// product argument"), and the FFT domains.
		pk, vk, err := plonk.Setup(ccs, &srs, &srsLagrange)
		//_, err := plonk.Setup(r1cs, kate, &publicWitness)
		if err != nil {
			log.Fatal(err)
		}

		proof, err := plonk.Prove(ccs, pk, witnessFull)
		if err != nil {
			log.Fatal(err)
		}

		err = plonk.Verify(proof, vk, witnessPublic)
		if err != nil {
			log.Fatal(err)
		}
	}
	// Wrong data: the proof fails
	{
		// Witnesses instantiation. Witness is known only by the prover,
		// while public w is a public data known by the verifier.
		var w, pW Circuit
		w.X = 2
		w.E = 12
		w.Y = 4096

		pW.X = 3
		pW.Y = 4096

		witnessFull, err := frontend.NewWitness(&w, ecc.BLS12_381.ScalarField())
		if err != nil {
			log.Fatal(err)
		}

		witnessPublic, err := frontend.NewWitness(&pW, ecc.BLS12_381.ScalarField(), frontend.PublicOnly())
		if err != nil {
			log.Fatal(err)
		}

		// public data consists of the polynomials describing the constants involved
		// in the constraints, the polynomial describing the permutation ("grand
		// product argument"), and the FFT domains.
		pk, vk, err := plonk.Setup(ccs, &srs, &srsLagrange)
		//_, err := plonk.Setup(r1cs, kate, &publicWitness)
		if err != nil {
			log.Fatal(err)
		}

		proof, err := plonk.Prove(ccs, pk, witnessFull)
		if err != nil {
			log.Fatal(err)
		}

		err = plonk.Verify(proof, vk, witnessPublic)
		if err == nil {
			log.Fatal("Error: wrong proof is accepted")
		}
	}
}
