package comdoc_test

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"testing"
	"testing/iotest"

	"github.com/sassoftware/relic/v7/lib/comdoc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStreamRead(t *testing.T) {
	f, err := comdoc.ReadPath("../../functest/packages/dummy.msi")
	require.NoError(t, err)
	files, err := f.ListDir(nil)
	require.NoError(t, err)
	// go through all the files once and collect the content
	contents := make([][]byte, len(files))
	for i, ff := range files {
		reader, err := f.ReadStream(ff)
		require.NoError(t, err)
		buf := make([]byte, ff.StreamSize)
		_, err = io.ReadFull(reader, buf)
		require.NoError(t, err)
		contents[i] = buf
	}
	t.Run("OddSectors", func(t *testing.T) {
		b := new(bytes.Buffer)
		// ensure a mix of full and partial sectors is used
		buf := make([]byte, f.SectorSize+1)
		for i, ff := range files {
			reader, err := f.ReadStream(ff)
			require.NoError(t, err)
			b.Reset()
			n, err := io.CopyBuffer(nonReaderFrom{w: b}, reader, buf)
			require.NoError(t, err)
			assert.Equal(t, int64(ff.StreamSize), n)
			assert.Equal(t, contents[i], b.Bytes())
		}
	})
	t.Run("SmallReads", func(t *testing.T) {
		for i, ff := range files {
			reader, err := f.ReadStream(ff)
			require.NoError(t, err)
			assert.NoError(t, iotest.TestReader(reader, contents[i]))
		}
	})
	require.NoError(t, f.Close())
}

// hide ReadFrom method so CopyBuffer uses the provided buffer
type nonReaderFrom struct{ w io.Writer }

func (w nonReaderFrom) Write(d []byte) (int, error) { return w.w.Write(d) }

func TestTruncated(t *testing.T) {
	f, err := os.Open("../../functest/packages/dummy.msi")
	require.NoError(t, err)
	defer f.Close()
	info, err := f.Stat()
	require.NoError(t, err)
	// vary how many bytes are chopped off
	for _, shortenBy := range []int64{1, 4095, 4097} {
		// exercise both full and partial sector errors
		for _, bufSize := range []int{4096, 1023} {
			t.Run(fmt.Sprintf("%d-%d", shortenBy, bufSize), func(t *testing.T) {
				buf := make([]byte, bufSize)
				trunc := truncatedReaderAt{r: f, size: info.Size() - shortenBy}
				cdf, err := comdoc.ReadFile(trunc)
				require.NoError(t, err)
				files, err := cdf.ListDir(nil)
				require.NoError(t, err)
				var someError error
				for _, ff := range files {
					reader, err := cdf.ReadStream(ff)
					require.NoError(t, err)
					if _, err := io.CopyBuffer(nonReaderFrom{w: io.Discard}, reader, buf); err != nil {
						someError = err
					}
				}
				assert.ErrorContains(t, someError, "short read")
			})
		}
	}
}

type truncatedReaderAt struct {
	r    io.ReaderAt
	size int64
}

// pretend the file is shorter
func (r truncatedReaderAt) ReadAt(d []byte, offset int64) (int, error) {
	dlen := int64(len(d))
	overage := offset + dlen - r.size
	if overage > dlen {
		return 0, io.EOF
	} else if overage > 0 {
		dlen -= overage
		d = d[:int(dlen)]
	}
	return r.r.ReadAt(d, offset)
}
