package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
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
	ClientTargetAddress string            `json:"client_target_address"`
	HandshakePort       int               `json:"handshake_port"`
	AuthKey             string            `json:"auth_key"`
	PortHopping         PortHoppingConfig `json:"port_hopping"`
}

// --- Sesi Klien & Retransmisi (Diperbarui) ---
type RetransmissionInfo struct {
	Packet      []byte
	SentTime    time.Time
	Retries     int
}

type ClientSession struct {
	sync.Mutex
	SessionID             string
	SharedKey             [crypto.KeySize]byte
	
	// State untuk Mengirim ke Server
	CurrentPort           int
	Sequence              uint64
	LastSentHash          [protocol.HashSize]byte
	PendingRetransmission map[uint64]*RetransmissionInfo // Antrean untuk paket yang menunggu ACK

	// State untuk Menerima dari Server
	ServerLastReceivedHash [protocol.HashSize]byte
	ServerExpectedSeq      uint64
}

// (loadConfig, PortSelector tidak berubah)
func loadConfig(path string) (*Config, error) { file, err := os.Open(path); if err != nil { return nil, err }; defer file.Close(); config := &Config{}; decoder := json.NewDecoder(file); err = decoder.Decode(config); return config, err }
type PortSelector struct{ start, end int }
func NewPortSelector(start, end int) *PortSelector { return &PortSelector{start: start, end: end} }
func (ps *PortSelector) GetNextPort() uint16 { return uint16(rand.Intn(ps.end-ps.start+1) + ps.start) }


// listenForAcks sekarang memverifikasi rantai hash server dan menghapus dari antrean retransmisi
func listenForAcks(conn *net.UDPConn, session *ClientSession) {
	log.Printf("Listener ACK berjalan di %s", conn.LocalAddr().String())
	buffer := make([]byte, 2048)
	for {
		n, _, err := conn.ReadFromUDP(buffer)
		if err != nil { continue }
		
		packetBytes := buffer[:n]
		packet, err := protocol.Deserialize(packetBytes)
		if err != nil { continue }
		
		plaintext, err := crypto.Decrypt(session.SharedKey, packet.Nonce, packet.Payload)
		if err != nil { continue }
		
		msg, err := protocol.DecodeDataMessage(plaintext)
		if err != nil { continue }

		session.Lock()

		// Verifikasi rantai hash dari server
		if !bytes.Equal(packet.Header.PrevHash[:], session.ServerLastReceivedHash[:]) {
			log.Printf("⚠️  Rantai hash dari server putus! Paket balasan ditolak.")
			session.Unlock()
			continue
		}
		if msg.Seq != session.ServerExpectedSeq {
			log.Printf("⚠️  Nomor urut dari server salah! Paket balasan ditolak.")
			session.Unlock()
			continue
		}
		
		// Perbarui state penerimaan dari server
		session.ServerLastReceivedHash = blake3.Sum256(packetBytes)
		session.ServerExpectedSeq++

		// Cek apakah ini adalah ACK untuk salah satu paket kita
		if _, ok := session.PendingRetransmission[msg.AckSeq]; ok {
			log.Printf("✅ Diterima: ACK untuk pesan #%d", msg.AckSeq)
			delete(session.PendingRetransmission, msg.AckSeq) // Hapus dari antrean
		}
		session.Unlock()
	}
}

// retransmissionChecker memeriksa paket yang belum di-ACK
func retransmissionChecker(session *ClientSession) {
	ticker := time.NewTicker(10 * time.Second) // Cek setiap 10 detik
	defer ticker.Stop()

	for range ticker.C {
		session.Lock()
		if len(session.PendingRetransmission) > 0 {
			log.Printf("⚠️  Pengecekan Retransmisi: %d paket menunggu ACK.", len(session.PendingRetransmission))
			for seq, info := range session.PendingRetransmission {
				if time.Since(info.SentTime) > 15*time.Second { // Timeout 15 detik
					log.Printf("❌ Paket #%d (retries: %d) dianggap hilang. Belum ada ACK setelah 15 detik.", seq, info.Retries)
					info.Retries++
					// Di sinilah logika pengiriman ulang yang sebenarnya akan ditempatkan.
					// Karena kompleksitas dengan port hopping, untuk saat ini kita hanya mencatatnya.
				}
			}
		}
		session.Unlock()
	}
}

func main() {
	rand.Seed(time.Now().UnixNano())
	log.Println("Memulai SecureFlow Client (Full State)...")
	config, err := loadConfig("configs/config.json")
	if err != nil { log.Fatalf("Gagal memuat konfigurasi: %v", err) }

	// --- 1. Membuat Listener ACK ---
	ackAddr, _ := net.ResolveUDPAddr("udp", "0.0.0.0:0")
	ackConn, _ := net.ListenUDP("udp", ackAddr)
	defer ackConn.Close()
	finalAckAddr := ackConn.LocalAddr().String()

	// --- 2. Handshake ---
	handshakeAddrStr := fmt.Sprintf("%s:%d", config.ClientTargetAddress, config.HandshakePort)
	serverAddr, _ := net.ResolveUDPAddr("udp", handshakeAddrStr)
	conn, _ := net.DialUDP("udp", nil, serverAddr)
	privKey, pubKey, _ := crypto.GenerateKeys()
	initialHash := [protocol.HashSize]byte{}
	handshakePacket := &protocol.SecurePacket{ Header: protocol.PacketHeader{Version: protocol.ProtocolVersion, Type: protocol.HandshakeMsgType, PrevHash: initialHash}, Payload: pubKey[:] }
	packetBytes, _ := handshakePacket.Serialize()
	conn.Write(packetBytes)
	buffer := make([]byte, 2048)
	n, _ := conn.Read(buffer)
	conn.Close()

	// --- 3. Inisialisasi Sesi ---
	responsePacket, _ := protocol.Deserialize(buffer[:n])
	var serverPubKey [crypto.KeySize]byte
	copy(serverPubKey[:], responsePacket.Payload[:crypto.KeySize])
	sharedKey, _ := crypto.SharedSecret(privKey, serverPubKey)
	
	session := &ClientSession{
		SessionID:             string(responsePacket.Payload[crypto.KeySize+2:]),
		SharedKey:             sharedKey,
		CurrentPort:           int(binary.BigEndian.Uint16(responsePacket.Payload[crypto.KeySize : crypto.KeySize+2])),
		Sequence:              0,
		LastSentHash:          initialHash,
		PendingRetransmission: make(map[uint64]*RetransmissionInfo),
		ServerLastReceivedHash: initialHash, // Rantai hash server juga dimulai dengan nol
		ServerExpectedSeq:      0,
	}

	go listenForAcks(ackConn, session)
	go retransmissionChecker(session)
	log.Printf("Handshake berhasil. SessionID: %s, Port Pertama: %d", session.SessionID, session.CurrentPort)

	// --- 4. Loop Pengiriman Pesan ---
	portSelector := NewPortSelector(config.PortHopping.Start, config.PortHopping.End)
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Ketik pesan dan tekan Enter untuk mengirim:")
	for {
		fmt.Print("> ")
		message, _ := reader.ReadString('\n')
		if len(message) == 0 { continue }

		session.Lock()
		currentSeq := session.Sequence
		dataMsg := &protocol.DataMessage{
			SessionID:  session.SessionID,
			Message:    []byte(message),
			NextPort:   portSelector.GetNextPort(),
			Seq:        currentSeq,
			AckSeq:     session.ServerExpectedSeq - 1, // Meng-ACK pesan terakhir dari server
			ReturnAddr: finalAckAddr,
		}
		plaintext, _ := protocol.EncodeDataMessage(dataMsg)
		encryptedPayload, nonce, _ := crypto.Encrypt(session.SharedKey, plaintext)
		dataPacket := &protocol.SecurePacket{
			Header: protocol.PacketHeader{ Version: protocol.ProtocolVersion, Type: protocol.DataMsgType, PrevHash: session.LastSentHash },
			Nonce:   nonce,
			Payload: encryptedPayload,
		}
		finalPacketBytes, _ := dataPacket.Serialize()

		session.PendingRetransmission[currentSeq] = &RetransmissionInfo{
			Packet:   finalPacketBytes,
			SentTime: time.Now(),
		}

		targetAddrStr := fmt.Sprintf("%s:%d", config.ClientTargetAddress, session.CurrentPort)
		targetAddr, _ := net.ResolveUDPAddr("udp", targetAddrStr)
		sendConn, _ := net.DialUDP("udp", nil, targetAddr)
		_, err = sendConn.Write(finalPacketBytes)
		sendConn.Close()
		if err != nil {
			log.Printf("Gagal mengirim data: %v", err)
			delete(session.PendingRetransmission, currentSeq)
			session.Unlock()
			continue
		}
		log.Printf("Pesan (seq #%d) terkirim. Menunggu ACK...", currentSeq)

		session.LastSentHash = blake3.Sum256(finalPacketBytes)
		session.CurrentPort = int(dataMsg.NextPort)
		session.Sequence++
		session.Unlock()
	}
}
