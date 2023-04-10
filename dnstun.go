package dnstun

import (
	"bytes"
	"github.com/kost/chashell/lib/crypto"
	"github.com/kost/chashell/lib/logging"
	"github.com/kost/chashell/lib/protocol"
	"github.com/kost/chashell/lib/transport"
	"encoding/hex"
	"math/rand"
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/miekg/dns"
	"strconv"
	"strings"
	"sync"
	"time"
	"net"
	"io"
	"log"

	"errors"

	"github.com/hashicorp/yamux"
	"github.com/acomagu/bufpipe"
)

const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// RandBytes generates random bytes of n size
// It returns the generated random bytes
func RandBytes(n int) []byte {
	r := make([]byte, n)
	_, err := rand.Read(r)
	if err != nil {
	}

	return r
}

type MemBuffer struct {
	r *bufpipe.PipeReader
	w *bufpipe.PipeWriter
}


type DnsTunnel struct {
	TargetDomain  string
	EncryptionKey string
	PortNum int
	PortInc int
	ClientsListen string
	Dns *dns.Server
	Transport *transport.DnsStream
	Sleeptime time.Duration
	Yamuxconfig *yamux.Config
	ReadBuffer map[string]MemBuffer
	// Store the packets that will be sent when the client send a polling request.
	packetQueue map[string][]string
	// Store the sessions information.
	sessionsMap map[string]*clientInfo
	// Temporary store the polled query. Some DNS Servers will perform multiples DNS requests for one query.
	// We need to send the same query to every requests or the Chashell client will not receive the data.
	pollCache map[string]*pollTemporaryData
}

type clientInfo struct {
	hostname  string
	heartbeat int64
	mutex     sync.Mutex
	conn      map[int32]connData
}

type Sessioninfo struct {
	opened bool
	id string
	dt *DnsTunnel
}

type connData struct {
	chunkSize int32
	nonce     []byte
	packets   map[int32]string
}

type pollTemporaryData struct {
	lastseen int64
	data string
}

func (ci *clientInfo) GetChunk(chunkID int32) connData {
	// Return the chunk identifier.
	return ci.conn[chunkID]
}

func YamuxConfig() *yamux.Config {
	yconfig:=yamux.DefaultConfig()
	yconfig.KeepAliveInterval=300 * time.Second
	yconfig.ConnectionWriteTimeout=120 * time.Second
	yconfig.StreamOpenTimeout=175 * time.Second
	yconfig.EnableKeepAlive=false
	return yconfig
}

func (dt *DnsTunnel) ParseQuery(m *dns.Msg) Sessioninfo {
	var newsession Sessioninfo
	for _, q := range m.Question {
		switch q.Qtype {
		// Make sure the request is a TXT question.
		case dns.TypeTXT:
			// logging.Printf("Got data packet: %s %s", q.Name, TargetDomain)
			// Strip the target domain and every dots.
			dataPacket := strings.Replace(strings.Replace(q.Name, dt.TargetDomain, "", -1), ".", "", -1)

			// Hex-decode the packet.
			dataPacketRaw, err := hex.DecodeString(dataPacket)

			if err != nil {
				logging.Printf("Unable to decode data packet : %s", dataPacket)
			}
			if len(dataPacketRaw)<24 {
				logging.Printf("Size not enough for data packet : %s", dataPacket)
				break
			}

			// Attempt to decrypt and authenticate the packet.
			output, valid := crypto.Open(dataPacketRaw[24:], dataPacketRaw[:24], dt.EncryptionKey)

			if !valid {
				logging.Printf("Received invalid/corrupted packet. Dropping. %s\n",dataPacket)
				break
			}

			// Return the decoded protocol buffers packet.
			message := &protocol.Message{}
			if err := proto.Unmarshal(output, message); err != nil {
				logging.Printf("Failed to parse message packet:", err)
				break
			}

			// Generic answer.
			answer := "-"

			// Hex-encode the clientGUID to make it printable.
			clientGUID := hex.EncodeToString(message.Clientguid)

			if clientGUID == "" {
				logging.Println("Invalid packet : empty clientGUID !")
				break
			}

			now := time.Now()

			// Check if the clientGUID exist in the session storage.
			session, valid := dt.sessionsMap[clientGUID]

			// If this this a new client, create the associated session.
			if !valid {
				logging.Printf("New session : %s\n", clientGUID)
				dt.sessionsMap[clientGUID] = &clientInfo{heartbeat: now.Unix(), conn: make(map[int32]connData)}
				tmpbuf := MemBuffer{}
				tmpbuf.r, tmpbuf.w = bufpipe.New(nil)
				dt.ReadBuffer[clientGUID] = tmpbuf
				session = dt.sessionsMap[clientGUID]
				newsession=Sessioninfo{opened: true, id: clientGUID, dt: dt}
			}

			// Avoid race conditions.
			session.mutex.Lock()

			// Update the heartbeat of the session.
			session.heartbeat = now.Unix()

			// Identify the message type.
			switch u := message.Packet.(type) {
			case *protocol.Message_Pollquery:
				// Check if this DNS poll-request was already performed.
				temp, valid := dt.pollCache[string(dataPacketRaw)]
				if valid {
					logging.Println("Duplicated poll query received.")
					// Send already in cache data.
					answer = temp.data
					break
				}

				// Check if we have data to send.
				queue, valid := dt.packetQueue[clientGUID]

				if valid && len(queue) > 0 {
					answer = queue[0]
					// Store answer in cache for DNS servers which are sending multiple queries.
					dt.pollCache[string(dataPacketRaw)] = &pollTemporaryData{lastseen: now.Unix(), data: answer}
					// Dequeue.
					dt.packetQueue[clientGUID] = queue[1:]
				}
			case *protocol.Message_Infopacket:
				session.hostname = string(u.Infopacket.Hostname)

			case *protocol.Message_Chunkstart:
				// Some DNS Servers will send multiple DNS queries, ignore duplicates.
				_, valid := session.conn[u.Chunkstart.Chunkid]
				if valid {
					logging.Printf("Ignoring duplicated Chunkstart : %d\n", u.Chunkstart.Chunkid)
					break
				}

				// We need to allocate a new session in order to store incoming data.
				session.conn[u.Chunkstart.Chunkid] = connData{chunkSize: u.Chunkstart.Chunksize, packets: make(map[int32]string)}


			case *protocol.Message_Chunkdata:
				// Get the storage associated to the chunkId.
				connection := session.GetChunk(u.Chunkdata.Chunkid)

				// Some DNS Servers will send multiple DNS queries, ignore duplicates.
				_, valid := connection.packets[u.Chunkdata.Chunknum]
				if valid {
					logging.Printf("Ignoring duplicated Chunkdata : %v\n", u.Chunkdata)
					break
				}

				// Store the data packet.
				connection.packets[u.Chunkdata.Chunknum] = string(u.Chunkdata.Packet)

				// Check if we have successfully received all the packets.
				if len(connection.packets) == int(connection.chunkSize) {
					// Rebuild the final data.
					var chunkBuffer bytes.Buffer
					for i := 0; i <= int(connection.chunkSize)-1; i++ {
						chunkBuffer.WriteString(connection.packets[int32(i)])
					}
					dt.ReadBuffer[clientGUID].w.Write(chunkBuffer.Bytes())
				}


			default:
				logging.Printf("Unknown message type received : %v\n", u)
			}
			// Unlock the mutex.
			session.mutex.Unlock()

			rr, _ := dns.NewRR(fmt.Sprintf("%s TXT %s", q.Name, answer))
			m.Answer = append(m.Answer, rr)

		}

	}
	return newsession
}

func (dt *DnsTunnel) HandleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		ns:=dt.ParseQuery(m)
		if ns!= (Sessioninfo{}) {
			logging.Printf("New session: %s", ns.id)
			session, erry := yamux.Client(&ns, dt.Yamuxconfig)
			if erry != nil {
				logging.Printf("[%s] Error creating client in yamux for %s: %v", ns.id,  erry)
			}
			go ListenForClients(ns.id, dt.ClientsListen, dt.PortNum+dt.PortInc, session)
			dt.PortInc = dt.PortInc + 1
		}
	}
	w.WriteMsg(m)
}

func (si *Sessioninfo) Read(data []byte) (int, error) {
	if ! si.opened {
		return 0, errors.New("read after close")
	}
	_, valid := si.dt.ReadBuffer[si.id]
	if !valid {
		return 0, errors.New("read of nonexistant or timed out connection")
	}
	nread, er:=si.dt.ReadBuffer[si.id].r.Read(data)
	return nread, er
}

func (si *Sessioninfo) Write(data []byte) (int, error) {
	if ! si.opened {
		return 0, errors.New("write after close")
	}
	initPacket, dataPackets := transport.Encode(data, false, si.dt.EncryptionKey, si.dt.TargetDomain, nil)
	_, valid := si.dt.packetQueue[si.id]
	if !valid {
		si.dt.packetQueue[si.id] = make([]string, 0)
		// return 0, errors.New("packetQueue does not exist")
	}
	si.dt.packetQueue[si.id] = append(si.dt.packetQueue[si.id], initPacket)
	for _, packet := range dataPackets {
		si.dt.packetQueue[si.id] = append(si.dt.packetQueue[si.id], packet)
	}
	return len(data), nil
}

func (si *Sessioninfo) Close() (error) {
	si.opened=false
	return nil
}

// Function - Timeout checking loop
func (dt *DnsTunnel) DnsTimeoutCheck() {
	for {
		time.Sleep(1 * time.Second)
		now := time.Now()
		for clientGUID, session := range dt.sessionsMap {
			if session.heartbeat+30 < now.Unix() {
				logging.Printf("Client timed out [%s].\n", clientGUID)
				// Delete from sessions list.
				delete(dt.sessionsMap, clientGUID)
				// Delete all queued packets.
				delete(dt.packetQueue, clientGUID)
			}
		}
	}
}

// Function - Poll-cache cleaner
func (dt *DnsTunnel) PollCacheCleaner() {
	for {
		time.Sleep(1 * time.Second)
		now := time.Now()
		for pollData, cache := range dt.pollCache {
			if cache.lastseen + 10 < now.Unix() {
				logging.Printf("Dropping cached poll query : %v\n", pollData)
				// Delete from poll cache list.
				delete(dt.pollCache, pollData)
			}
		}
	}
}

func (dt *DnsTunnel) SetDnsConfig(DnsDomain string, enckey string) {
	dt.TargetDomain = DnsDomain
	dt.EncryptionKey = enckey
}

func GenerateKey() (string) {
	rb:=RandBytes(32)
	rbhex:=hex.EncodeToString(rb)
	return rbhex
}

func (dt *DnsTunnel) SetDnsDelay (dnsdelay string) error {
	if dnsdelay == "" {
		return errors.New("empty duration")
	}
	dur, err := time.ParseDuration(dnsdelay)
	if err != nil {
		return err
	}
	dt.Sleeptime=dur
	// if transport is initialized set it directly
	if dt.Transport != nil {
		dt.Transport.SetSleeptime(dur)
	}
	return nil
}

func (dt *DnsTunnel) DnsServer (dnslisten string, clients string) (error) {
	var listenstr = strings.Split(clients, ":")
	portnum, errc := strconv.Atoi(listenstr[1])
	if errc != nil {
		return errors.New("Error converting listen DNS listen string")
	}

	dt.PortNum = portnum
	dt.PortInc = 0
	dt.ClientsListen = listenstr[0]

	dns.HandleFunc(dt.TargetDomain, dt.HandleDnsRequest)
	dt.Dns = &dns.Server{Addr: dnslisten, Net: "udp"}

	return nil
}

func (dt *DnsTunnel) DnsServerStart () error {
	// start helping routines for timeouts
	go dt.DnsTimeoutCheck()
	go dt.PollCacheCleaner()

	// start server
	err := dt.Dns.ListenAndServe()
	defer dt.Dns.Shutdown()
	return err
}

func (dt *DnsTunnel) DnsClient () (*yamux.Session, error) {
	dt.Transport = transport.DNSStream(dt.TargetDomain, dt.EncryptionKey)
	dt.Transport.SetSleeptime(dt.Sleeptime)
	session, err := yamux.Server(dt.Transport, dt.Yamuxconfig)
	return session, err
}

func NewDnsTunnel(targetDomain string, encryptionKey string) *DnsTunnel {
	dt:=DnsTunnel{}
	dt.sessionsMap=make(map[string]*clientInfo)
	dt.ReadBuffer=make(map[string]MemBuffer)
	dt.packetQueue=make(map[string][]string)
	dt.pollCache=make(map[string]*pollTemporaryData)
	dt.SetDnsConfig(targetDomain, encryptionKey)
	dt.Sleeptime = 200 * time.Millisecond
	dt.Yamuxconfig=YamuxConfig()
	return &dt
}

// Catches local clients and connects to yamux
func ListenForClients(agentstr string, listen string, port int, session *yamux.Session) error {
	var ln net.Listener
	var address string
	var err error
	portinc := port
	for {
		address = fmt.Sprintf("%s:%d", listen, portinc)
		log.Printf("[%s] Waiting for clients on %s", agentstr, address)
		ln, err = net.Listen("tcp", address)
		if err != nil {
			log.Printf("[%s] Error listening on %s: %v", agentstr, address, err)
			portinc = portinc + 1
		} else {
			break
		}
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			logging.Printf("[%s] Error accepting on %s: %v", agentstr, address, err)
			return err
		}
		if session == nil {
			logging.Printf("[%s] Session on %s is nil", agentstr, address)
			conn.Close()
			continue
		}
		logging.Printf("[%s] Got client. Opening stream for %s", agentstr, conn.RemoteAddr())

		stream, err := session.Open()
		if err != nil {
			logging.Printf("[%s] Error opening stream for %s: %v", agentstr, conn.RemoteAddr(), err)
			return err
		}

		// connect both of conn and stream

		go func() {
			logging.Printf("[%s] Starting to copy conn to stream for %s", agentstr, conn.RemoteAddr())
			io.Copy(conn, stream)
			conn.Close()
			logging.Printf("[%s] Done copying conn to stream for %s", agentstr, conn.RemoteAddr())
		}()
		go func() {
			logging.Printf("[%s] Starting to copy stream to conn for %s", agentstr, conn.RemoteAddr())
			io.Copy(stream, conn)
			stream.Close()
			logging.Printf("[%s] Done copying stream to conn for %s", agentstr, conn.RemoteAddr())
		}()
	}
}

