package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/eikarna/SecureFlow/internal/crypto"
)

const (
	ProtocolVersion    = 1
	HandshakeMsgType   = 0x01
	DataMsgType        = 0x02
	HandshakePublicKeySize = crypto.KeySize
)

// PacketHeader adalah header untuk setiap paket SecureFlow.
type PacketHeader struct {
	Version   uint8
	Type      uint8
	NonceSize uint16
	Length    uint16 // Panjang dari sisa paket (Nonce + Payload)
}

// SecurePacket merepresentasikan satu unit data yang dikirim.
type SecurePacket struct {
	Header    PacketHeader
	Nonce     []byte
	Payload   []byte // Bisa berupa public key (handshake) atau data terenkripsi
	// TODO: Tambahkan Prev_Hash (32B) untuk chaining
}

// Serialize mengubah SecurePacket menjadi byte slice untuk dikirim.
func (p *SecurePacket) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)
	p.Header.NonceSize = uint16(len(p.Nonce))
	p.Header.Length = uint16(len(p.Nonce)) + uint16(len(p.Payload))

	if err := binary.Write(buf, binary.BigEndian, p.Header); err != nil {
		return nil, fmt.Errorf("gagal menulis header: %w", err)
	}
	if _, err := buf.Write(p.Nonce); err != nil {
		return nil, fmt.Errorf("gagal menulis nonce: %w", err)
	}
	if _, err := buf.Write(p.Payload); err != nil {
		return nil, fmt.Errorf("gagal menulis payload: %w", err)
	}

	return buf.Bytes(), nil
}

// Deserialize mengubah byte slice menjadi SecurePacket.
func Deserialize(data []byte) (*SecurePacket, error) {
	if len(data) < binary.Size(PacketHeader{}) {
		return nil, fmt.Errorf("data terlalu pendek untuk header: %d", len(data))
	}

	reader := bytes.NewReader(data)
	var header PacketHeader
	if err := binary.Read(reader, binary.BigEndian, &header); err != nil {
		return nil, fmt.Errorf("gagal membaca header: %w", err)
	}

	if header.Version != ProtocolVersion {
		return nil, fmt.Errorf("versi protokol tidak cocok: diterima %d, diharapkan %d", header.Version, ProtocolVersion)
	}

	expectedLen := int(header.Length)
	remainingLen := reader.Len()
	if remainingLen != expectedLen {
		return nil, fmt.Errorf("panjang paket tidak cocok: diterima %d, diharapkan %d", remainingLen, expectedLen)
	}

	nonce := make([]byte, header.NonceSize)
	if _, err := io.ReadFull(reader, nonce); err != nil {
		return nil, fmt.Errorf("gagal membaca nonce: %w", err)
	}

	payload := make([]byte, int(header.Length)-int(header.NonceSize))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, fmt.Errorf("gagal membaca payload: %w", err)
	}

	return &SecurePacket{
		Header:  header,
		Nonce:   nonce,
		Payload: payload,
	}, nil
}
