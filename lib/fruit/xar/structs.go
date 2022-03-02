package xar

type fileHeader struct {
	Magic            uint32
	HeaderSize       uint16
	Version          uint16
	CompressedSize   int64
	UncompressedSize int64
	HashType         hashType
}

const xarMagic = 0x78617221 // xar!

type hashType uint32

//nolint:deadcode,varcheck // for doc purposes
const (
	hashNone hashType = iota
	hashSHA1
	hashMD5
	hashSHA256
	hashSHA512
)

type tocXar struct {
	TOC tocToc `xml:"toc"`
}

type tocToc struct {
	CreationTime string        `xml:"creation-time"`
	Checksum     tocChecksum   `xml:"checksum"`
	Signature    *tocSignature `xml:"signature"`
	XSignature   *tocSignature `xml:"x-signature"`

	Files []*tocFile `xml:"file"`
}

type tocChecksum struct {
	Style  string `xml:"style,attr"`
	Offset int64  `xml:"offset"`
	Size   int64  `xml:"size"`
}

type tocSignature struct {
	Style        string   `xml:"style,attr"`
	Offset       int64    `xml:"offset"`
	Size         int64    `xml:"size"`
	Certificates []string `xml:"KeyInfo>X509Data>X509Certificate,omitempty"`
}

type tocFile struct {
	Name string `xml:"name"`
	Type string `xml:"type"`

	ArchivedChecksum  tocFileSum  `xml:"data>archived-checksum"`
	ExtractedChecksum tocFileSum  `xml:"data>extracted-checksum"`
	Encoding          tocEncoding `xml:"data>encoding"`
	Size              int64       `xml:"data>size"`
	Offset            int64       `xml:"data>offset"`
	Length            int64       `xml:"data>length"`

	Files []*tocFile `xml:"file"`
}

type tocEncoding struct {
	Style string `xml:"style,attr"`
}

type tocFileSum struct {
	Style  string `xml:"style,attr"`
	Digest string `xml:",chardata"`
}
