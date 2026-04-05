package blobpack

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/Naveen-6087/kzg-blobs/kzg"
)

// Layout: every field element is 0x00 followed by 31 payload bytes, so it is
// always canonical. The payload stream is an 8-byte big-endian length, the
// data, then zero padding, spread over the minimum number of blobs.
const (
	bytesPerElement    = kzg.BytesPerFieldElement - 1
	UsableBytesPerBlob = kzg.FieldElementsPerBlob * bytesPerElement
	lengthPrefix       = 8
)

var (
	ErrTooLarge  = errors.New("blobpack: data too large")
	ErrMalformed = errors.New("blobpack: malformed blobs")
)

func BlobsNeeded(n int) int {
	total := n + lengthPrefix
	return (total + UsableBytesPerBlob - 1) / UsableBytesPerBlob
}

// Pack splits data into blobs. maxBlobs of 0 means no limit.
func Pack(data []byte, maxBlobs int) ([]kzg.Blob, error) {
	n := BlobsNeeded(len(data))
	if maxBlobs > 0 && n > maxBlobs {
		return nil, fmt.Errorf("%w: %d bytes need %d blobs, limit is %d", ErrTooLarge, len(data), n, maxBlobs)
	}
	stream := make([]byte, n*UsableBytesPerBlob)
	binary.BigEndian.PutUint64(stream, uint64(len(data)))
	copy(stream[lengthPrefix:], data)

	blobs := make([]kzg.Blob, n)
	for b := range blobs {
		chunk := stream[b*UsableBytesPerBlob : (b+1)*UsableBytesPerBlob]
		for i := range kzg.FieldElementsPerBlob {
			copy(blobs[b][i*kzg.BytesPerFieldElement+1:(i+1)*kzg.BytesPerFieldElement],
				chunk[i*bytesPerElement:(i+1)*bytesPerElement])
		}
	}
	return blobs, nil
}

// Unpack reverses Pack and rejects anything Pack would not have produced.
func Unpack(blobs []kzg.Blob) ([]byte, error) {
	if len(blobs) == 0 {
		return nil, fmt.Errorf("%w: no blobs", ErrMalformed)
	}
	stream := make([]byte, 0, len(blobs)*UsableBytesPerBlob)
	for b := range blobs {
		for i := range kzg.FieldElementsPerBlob {
			fe := blobs[b][i*kzg.BytesPerFieldElement : (i+1)*kzg.BytesPerFieldElement]
			if fe[0] != 0 {
				return nil, fmt.Errorf("%w: blob %d element %d has a non-zero high byte", ErrMalformed, b, i)
			}
			stream = append(stream, fe[1:]...)
		}
	}
	length := binary.BigEndian.Uint64(stream)
	if length > uint64(len(stream)-lengthPrefix) {
		return nil, fmt.Errorf("%w: length %d exceeds capacity of %d blobs", ErrMalformed, length, len(blobs))
	}
	if want := BlobsNeeded(int(length)); want != len(blobs) {
		return nil, fmt.Errorf("%w: %d bytes should use %d blobs, got %d", ErrMalformed, length, want, len(blobs))
	}
	end := lengthPrefix + int(length)
	for i, c := range stream[end:] {
		if c != 0 {
			return nil, fmt.Errorf("%w: non-zero padding at offset %d", ErrMalformed, end+i)
		}
	}
	return append([]byte(nil), stream[lengthPrefix:end]...), nil
}
