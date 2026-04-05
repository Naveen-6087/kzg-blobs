package kzg_test

import (
	"fmt"
	"log"

	"github.com/Naveen-6087/kzg-blobs/blobpack"
	"github.com/Naveen-6087/kzg-blobs/kzg"
	"github.com/Naveen-6087/kzg-blobs/pointeval"
)

func Example() {
	ctx, err := kzg.DefaultContext()
	if err != nil {
		log.Fatal(err)
	}

	blobs, err := blobpack.Pack([]byte("Hello from an EIP-4844 blob!\n"), 6)
	if err != nil {
		log.Fatal(err)
	}
	commitment, err := ctx.BlobToCommitment(&blobs[0])
	if err != nil {
		log.Fatal(err)
	}
	proof, err := ctx.ComputeBlobKZGProof(&blobs[0], commitment)
	if err != nil {
		log.Fatal(err)
	}
	ok, err := ctx.VerifyBlobKZGProof(&blobs[0], commitment, proof)
	if err != nil {
		log.Fatal(err)
	}
	versionedHash := pointeval.VersionedHash(commitment)

	fmt.Println("valid:", ok)
	fmt.Printf("versioned hash: %x\n", versionedHash)
	// Output:
	// valid: true
	// versioned hash: 01c8e19a586c6e68ddcab53f098089df1ae5ab2ac094e6c4ad7638234c3f23a0
}
