package protocol

import (
	"log"
	"net"

	"github.com/eikarna/SecureFlow/internal/crypto"
)

// HandleServerHandshake menangani proses handshake di sisi server.
func HandleServerHandshake(conn *net.UDPConn, remoteAddr *net.UDPAddr, clientPubKey [crypto.KeySize]byte, serverPrivKey [crypto.KeySize]byte, serverPubKey [crypto.KeySize]byte) ([crypto.KeySize]byte, error) {
	// Membuat shared secret
	sharedKey, err := crypto.SharedSecret(serverPrivKey, clientPubKey)
	if err != nil {
		return [crypto.KeySize]byte{}, err
	}

	// Mengirim kembali public key server
	responsePacket := &SecurePacket{
		Header: PacketHeader{
			Version: ProtocolVersion,
			Type:    HandshakeMsgType,
		},
		Payload: serverPubKey[:],
	}

	packetBytes, err := responsePacket.Serialize()
	if err != nil {
		return [crypto.KeySize]byte{}, err
	}

	_, err = conn.WriteToUDP(packetBytes, remoteAddr)
	if err != nil {
		return [crypto.KeySize]byte{}, err
	}

	log.Printf("Handshake dengan %s berhasil. Shared key dibuat.", remoteAddr.String())
	return sharedKey, nil
}

// HandleClientHandshake menangani proses handshake di sisi klien.
func HandleClientHandshake(conn *net.UDPConn) ([crypto.KeySize]byte, error) {
	// Membuat kunci klien
	privKey, pubKey, err := crypto.GenerateKeys()
	if err != nil {
		return [crypto.KeySize]byte{}, err
	}

	// Mengirim kunci publik klien ke server
	handshakePacket := &SecurePacket{
		Header: PacketHeader{
			Version: ProtocolVersion,
			Type:    HandshakeMsgType,
		},
		Payload: pubKey[:],
	}

	packetBytes, err := handshakePacket.Serialize()
	if err != nil {
		return [crypto.KeySize]byte{}, err
	}
	_, err = conn.Write(packetBytes)
	if err != nil {
		return [crypto.KeySize]byte{}, err
	}
	log.Println("Mengirim public key ke server...")

	// Menerima kunci publik server
	buffer := make([]byte, 2048)
	n, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		return [crypto.KeySize]byte{}, err
	}

	responsePacket, err := Deserialize(buffer[:n])
	if err != nil {
		return [crypto.KeySize]byte{}, err
	}

	if responsePacket.Header.Type != HandshakeMsgType || len(responsePacket.Payload) != crypto.KeySize {
		log.Fatalf("Menerima paket handshake yang tidak valid dari server")
	}

	var serverPubKey [crypto.KeySize]byte
	copy(serverPubKey[:], responsePacket.Payload)
	log.Println("Menerima public key dari server.")

	// Membuat shared secret
	sharedKey, err := crypto.SharedSecret(privKey, serverPubKey)
	if err != nil {
		return [crypto.KeySize]byte{}, err
	}

	log.Println("Handshake berhasil, shared secret dibuat.")
	return sharedKey, nil
}
