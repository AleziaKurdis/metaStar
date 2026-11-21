package qtstream

import "testing"

// FuzzQtStreamReaders exercises every variable-length and fixed-length reader
// against arbitrary input. The target is intentionally panic-sensitive: any
// out-of-bounds access is reported by Go's fuzzing engine.
func FuzzQtStreamReaders(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{1, 192, 0, 2, 1, 0x1c, 0x9c})
	f.Add([]byte{2, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0x1c, 0x9c})
	f.Add([]byte{0, 0, 0, 4, 0xd8, 0x3d, 0xde, 0x80})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		for _, read := range []func(*Reader){
			func(r *Reader) { _, _, _ = r.UUID() },
			func(r *Reader) { _, _, _ = r.Socket() },
			func(r *Reader) { _, _ = r.QByteArray() },
			func(r *Reader) { _, _ = r.QString() },
		} {
			r := &Reader{B: data}
			read(r)
		}
		_, _ = UUIDBytes(string(data))
	})
}

func TestReaderRejectsInvalidOffsets(t *testing.T) {
	for _, offset := range []int{-1, 4} {
		r := Reader{B: []byte{1, 2, 3}, Off: offset}
		if _, err := r.QString(); err == nil {
			t.Fatalf("QString accepted invalid reader offset %d", offset)
		}
	}
}
