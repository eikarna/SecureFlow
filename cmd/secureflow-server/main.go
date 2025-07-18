package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/eikarna/SecureFlow/internal/crypto"
	"github.com/eikarna/SecureFlow/internal/protocol"
	"lukechampine.com/blake3"
)

// --- Konfigurasi (Tidak Berubah) ---
type PortHoppingConfig struct {
	Enabled bool `json:"enabled"`
	Start   int  `json:"start"`
	End     int  `json:"end"`
}
type Config struct {
	ListenAddress string            `json:"listen_address"`
	HandshakePort int               `json:"handshake_port"`
	AuthKey       string            `json:"auth_key"`
	PortHopping   PortHoppingConfig `json:"port_hopping"`
}

// --- Manajemen Sesi & Port (Sesi Diperbarui) ---
type ClientSession struct {
	sync.RWMutex
	// State untuk Menerima dari Klien
	LastReceivedHash [protocol.HashSize]byte
	ExpectedSeq      uint64
	SharedKey        [crypto.KeySize]byte

	// State untuk Mengirim ke Klien
	ServerLastSentHash [protocol.HashSize]byte
	ServerSequence     uint64
}

var (
	sessions      = make(map[string]*ClientSession)
	sessionsMutex = &sync.RWMutex{}
	initialHash   = [protocol.HashSize]byte{}
)

// (PortManager, loadConfig, generateSessionID tidak berubah)
type PortManager struct{ mu sync.Mutex; nextPort, start, end int }
func NewPortManager(start, end int) *PortManager { return &PortManager{nextPort: start, start: start, end: end} }
func (pm *PortManager) GetNextPort() int { pm.mu.Lock(); defer pm.mu.Unlock(); port := pm.nextPort; pm.nextPort++; if pm.nextPort > pm.end { pm.nextPort = pm.start }; return port }
func loadConfig(path string) (*Config, error) { file, err := os.Open(path); if err != nil { return nil, err }; defer file.Close(); config := &Config{}; decoder := json.NewDecoder(file); err = decoder.Decode(config); return config, err }
func generateSessionID() (string, error) { bytes := make([]byte, 16); if _, err := rand.Read(bytes); err != nil { return "", err }; return hex.EncodeToString(bytes), nil }


// --- Logika Inti Server (sendReply Diperbarui) ---

// sendReply mengirim balasan (biasanya hanya ACK) ke klien.
// Fungsi ini sekarang stateful dan membentuk rantai hash dari sisi server.
func sendReply(session *ClientSession, clientReturnAddr string, ackForSeq uint64) {
	session.Lock()
	defer session.Unlock()

	replyMsg := &protocol.DataMessage{
		SessionID:  "server-reply",
		Message:    nil,
		NextPort:   0,
		Seq:        session.ServerSequence,
		AckSeq:     ackForSeq,
		ReturnAddr: "",
	}
	plaintext, _ := protocol.EncodeDataMessage(replyMsg)
	encryptedPayload, nonce, _ := crypto.Encrypt(session.SharedKey, plaintext)

	replyPacket := &protocol.SecurePacket{
		Header: protocol.PacketHeader{
			Version:  protocol.ProtocolVersion,
			Type:     protocol.DataMsgType,
			PrevHash: session.ServerLastSentHash, // Menggunakan hash terakhir yang dikirim server
		},
		Nonce:   nonce,
		Payload: encryptedPayload,
	}
	packetBytes, _ := replyPacket.Serialize()

	// Perbarui state pengiriman server SEBELUM mengirim
	session.ServerLastSentHash = blake3.Sum256(packetBytes)
	session.ServerSequence++

	// Kirim balasan
	rAddr, err := net.ResolveUDPAddr("udp", clientReturnAddr)
	if err != nil {
		log.Printf("[Reply Sender] Gagal resolve alamat kembali klien %s: %v", clientReturnAddr, err)
		return
	}
	conn, err := net.DialUDP("udp", nil, rAddr)
	if err != nil {
		log.Printf("[Reply Sender] Gagal dial ke %s: %v", clientReturnAddr, err)
		return
	}
	defer conn.Close()
	conn.Write(packetBytes)
	log.Printf("🚀 Terkirim: Balasan (ACK untuk #%d, Seq #%d) ke %s", ackForSeq, replyMsg.Seq, clientReturnAddr)
}

// (handleHop tidak berubah secara signifikan, hanya pemanggilan sendReply)
func handleHop(listenAddr string, port int, config *Config) {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", listenAddr, port))
	if err != nil { log.Printf("[Port %d] Gagal resolve alamat: %v", port, err); return }
	conn, err := net.ListenUDP("udp", addr)
	if err != nil { log.Printf("[Port %d] Gagal mendengarkan: %v", port, err); return }
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
	buffer := make([]byte, 2048)
	n, remoteAddr, err := conn.ReadFromUDP(buffer)
	if err != nil { log.Printf("[Port %d] Tidak menerima paket: %v", port, err); return }
	packetBytes := buffer[:n]
	packet, err := protocol.Deserialize(packetBytes)
	if err != nil { log.Printf("[Port %d] Gagal deserialize: %v", port, err); return }
	if packet.Header.Type != protocol.DataMsgType { log.Printf("[Port %d] Menerima tipe paket salah", port); return }

	var dataMsg *protocol.DataMessage
	var session *ClientSession
	var sessionID string
	var found bool
	sessionsMutex.RLock()
	for id, s := range sessions {
		plaintext, err := crypto.Decrypt(s.SharedKey, packet.Nonce, packet.Payload)
		if err == nil {
			msg, err_decode := protocol.DecodeDataMessage(plaintext)
			if err_decode == nil { dataMsg, session, sessionID, found = msg, s, id, true; break }
		}
	}
	sessionsMutex.RUnlock()
	if !found { log.Printf("[Port %d] Gagal dekripsi paket dari %s.", port, remoteAddr); return }

	session.RLock()
	lastHash := session.LastReceivedHash
	expectedSeq := session.ExpectedSeq
	session.RUnlock()
	if !bytes.Equal(packet.Header.PrevHash[:], lastHash[:]) { log.Printf("[Session %s] Rantai hash putus!", sessionID); return }
	if dataMsg.Seq != expectedSeq { log.Printf("[Session %s] Nomor urut salah!", sessionID); return }

	log.Printf("[Session %s] Paket #%d OK.", sessionID, dataMsg.Seq)
	newHash := blake3.Sum256(packetBytes)
	session.Lock()
	session.LastReceivedHash = newHash
	session.ExpectedSeq++
	session.Unlock()
	fmt.Printf("Pesan dari %s (seq %d): %s", dataMsg.SessionID, dataMsg.Seq, string(dataMsg.Message))

	go sendReply(session, dataMsg.ReturnAddr, dataMsg.Seq)
	go handleHop(listenAddr, int(dataMsg.NextPort), config)
}


func main() {
	log.Println("Memulai SecureFlow Server (Full State)...")
	config, err := loadConfig("configs/config.json")
	if err != nil { log.Fatalf("Gagal memuat konfigurasi: %v", err) }
	handshakeAddrStr := fmt.Sprintf("%s:%d", config.ListenAddress, config.HandshakePort)
	addr, err := net.ResolveUDPAddr("udp", handshakeAddrStr)
	if err != nil { log.Fatalf("Gagal resolve alamat handshake: %v", err) }
	handshakeConn, err := net.ListenUDP("udp", addr)
	if err != nil { log.Fatalf("Gagal mendengarkan di port handshake: %v", err) }
	defer handshakeConn.Close()
	log.Printf("Server handshake mendengarkan di %s", handshakeAddrStr)
	serverPrivKey, serverPubKey, err := crypto.GenerateKeys()
	if err != nil { log.Fatalf("Gagal membuat kunci server: %v", err) }
	portMgr := NewPortManager(config.PortHopping.Start, config.PortHopping.End)
	log.Printf("Port hopping diaktifkan, rentang: %d-%d", config.PortHopping.Start, config.PortHopping.End)
	buffer := make([]byte, 2048)
	for {
		n, remoteAddr, err := handshakeConn.ReadFromUDP(buffer)
		if err != nil { log.Printf("Gagal membaca dari handshake conn: %v", err); continue }
		packet, err := protocol.Deserialize(buffer[:n])
		if err != nil { log.Printf("Gagal deserialize paket handshake dari %s: %v", remoteAddr, err); continue }
		if packet.Header.Type == protocol.HandshakeMsgType {
			var clientPubKey [crypto.KeySize]byte
			copy(clientPubKey[:], packet.Payload)
			sharedKey, _ := crypto.SharedSecret(serverPrivKey, clientPubKey)
			sessionID, _ := generateSessionID()
			sessionsMutex.Lock()
			sessions[sessionID] = &ClientSession{
				SharedKey:          sharedKey,
				LastReceivedHash:   initialHash,
				ExpectedSeq:        0,
				ServerLastSentHash: initialHash, // Inisialisasi state pengiriman server
				ServerSequence:     0,
			}
			sessionsMutex.Unlock()
			log.Printf("Handshake dengan %s berhasil. SessionID: %s", remoteAddr, sessionID)
			firstPort := portMgr.GetNextPort()
			portBytes := make([]byte, 2)
			binary.BigEndian.PutUint16(portBytes, uint16(firstPort))
			responsePayload := append(serverPubKey[:], portBytes...)
			responsePayload = append(responsePayload, []byte(sessionID)...)
			responsePacket := &protocol.SecurePacket{
				Header:  protocol.PacketHeader{Version: protocol.ProtocolVersion, Type: protocol.HandshakeMsgType, PrevHash: initialHash},
				Payload: responsePayload,
			}
			packetBytes, _ := responsePacket.Serialize()
			handshakeConn.WriteToUDP(packetBytes, remoteAddr)
			log.Printf("Mengalokasikan port pertama %d untuk session %s", firstPort, sessionID)
			go handleHop(config.ListenAddress, firstPort, config)
		}
	}
}